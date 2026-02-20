"""
MetaGuard - FastAPI application for metadata analysis and scrubbing.
"""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from analyzer import compute_sha256, extract_metadata
from file_validation import cleanup_file, save_uploaded_file
from rate_limiter import RateLimitError, check_rate_limit
from risk_engine import assess_risk
from scrubber import scrub_metadata
from security_logging import log_security_event

app = FastAPI(
    title="MetaGuard",
    description="Metadata analysis and scrubbing service for images, PDFs, and DOCX files",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


SCRUBBED_FILES: Dict[str, datetime] = {}
SCRUBBED_FILE_TTL_SECONDS = 300  # 5 minutes


def _get_client_ip(request: Request) -> str:
    """
    Extract the client IP address from the request.

    For simplicity and to avoid trust issues, this uses the direct client
    connection rather than X-Forwarded-For headers.
    """
    if request.client:
        return request.client.host
    return "unknown"


def _register_scrubbed_file(file_path: str) -> str:
    """
    Register a scrubbed file for secure download and track its expiration.

    Args:
        file_path: Full path to the scrubbed file.

    Returns:
        The scrubbed file's basename (secure filename).
    """
    filename = Path(file_path).name
    SCRUBBED_FILES[filename] = datetime.now(timezone.utc)
    return filename


def _is_expired(created_at: datetime) -> bool:
    """Return True if a scrubbed file created_at is past its TTL."""
    return created_at + timedelta(seconds=SCRUBBED_FILE_TTL_SECONDS) < datetime.now(
        timezone.utc
    )


def _cleanup_expired_files() -> None:
    """
    Delete expired scrubbed files from disk and registry.

    This enforces the 5-minute lifetime for downloadable scrubbed files.
    """
    temp_dir = Path(tempfile.gettempdir()) / "metaguard"
    now = datetime.now(timezone.utc)

    expired_keys = []
    for filename, created_at in list(SCRUBBED_FILES.items()):
        if created_at + timedelta(seconds=SCRUBBED_FILE_TTL_SECONDS) < now:
            file_path = temp_dir / filename
            cleanup_file(str(file_path))
            expired_keys.append(filename)

    for key in expired_keys:
        SCRUBBED_FILES.pop(key, None)


@app.get("/")
async def root():
    """Root endpoint redirects to interactive API documentation."""
    return RedirectResponse(url="/docs")


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Health check endpoint for monitoring and deployment verification.
    
    This endpoint is used by:
    - Monitoring systems to verify the service is running
    - Load balancers to check server health
    - Container orchestration platforms (Kubernetes, Docker Swarm) for readiness probes
    - CI/CD pipelines to confirm successful deployments
    
    Returns a simple status indicating the API is operational.
    """
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
) -> Dict[str, Any]:
    """
    Analyze uploaded file and extract metadata with risk assessment.

    Applies per-IP rate limiting and security logging.
    """
    ip = _get_client_ip(request)
    try:
        check_rate_limit(ip)
    except RateLimitError:
        log_security_event(
            "rate_limit_triggered",
            ip=ip,
            extra={"endpoint": "/analyze"},
        )
        raise HTTPException(status_code=429, detail="Too Many Requests")

    file_path: str | None = None
    try:
        # Save and validate uploaded file
        file_path, secure_filename = save_uploaded_file(file)

        # Compute original file hash
        original_hash = compute_sha256(file_path)

        # Extract metadata
        metadata = extract_metadata(file_path)

        # Assess risk
        risk_assessment = assess_risk(metadata)

        # Security logging
        log_security_event(
            "file_analyzed",
            ip=ip,
            file_type=metadata.get("file_type"),
            risk_level=risk_assessment.get("risk_level"),
            extra={
                "endpoint": "/analyze",
                "filename": file.filename,
                "risk_score": risk_assessment.get("risk_score"),
            },
        )

        # Prepare response
        response = {
            "filename": file.filename,
            "secure_filename": secure_filename,
            "original_file_hash": original_hash,
            "metadata": metadata,
            "risk_assessment": risk_assessment,
        }

        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    finally:
        # Cleanup original file
        if file_path:
            cleanup_file(file_path)


@app.post("/verify")
async def verify_file(
    request: Request,
    file: UploadFile = File(...),
) -> Dict[str, Any]:
    """
    Verify whether a file contains high-risk metadata.

    This endpoint reuses the analyzer and risk engine, but does NOT scrub files.
    """
    ip = _get_client_ip(request)
    try:
        check_rate_limit(ip)
    except RateLimitError:
        log_security_event(
            "rate_limit_triggered",
            ip=ip,
            extra={"endpoint": "/verify"},
        )
        raise HTTPException(status_code=429, detail="Too Many Requests")

    file_path: str | None = None
    try:
        # Save and validate uploaded file
        file_path, secure_filename = save_uploaded_file(file)

        # Compute original file hash
        original_hash = compute_sha256(file_path)

        # Extract metadata
        metadata = extract_metadata(file_path)

        # Assess risk
        risk_assessment = assess_risk(metadata)
        risk_level = risk_assessment.get("risk_level")
        high_risk = risk_level == "High"

        # Security logging
        log_security_event(
            "file_analyzed",
            ip=ip,
            file_type=metadata.get("file_type"),
            risk_level=risk_level,
            extra={
                "endpoint": "/verify",
                "filename": file.filename,
                "risk_score": risk_assessment.get("risk_score"),
            },
        )

        return {
            "filename": file.filename,
            "secure_filename": secure_filename,
            "original_file_hash": original_hash,
            "high_risk_metadata": high_risk,
            "risk_assessment": risk_assessment,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification error: {str(e)}")
    finally:
        if file_path:
            cleanup_file(file_path)


@app.post("/scrub")
async def scrub_file(
    request: Request,
    file: UploadFile = File(...),
) -> Dict[str, Any]:
    """
    Scrub metadata from uploaded file regardless of risk level.

    Applies per-IP rate limiting, logging, and secure download registration.
    All files are scrubbed to remove unnecessary metadata.
    """
    ip = _get_client_ip(request)
    try:
        check_rate_limit(ip)
    except RateLimitError:
        log_security_event(
            "rate_limit_triggered",
            ip=ip,
            extra={"endpoint": "/scrub"},
        )
        raise HTTPException(status_code=429, detail="Too Many Requests")

    file_path: str | None = None
    scrubbed_file_path: str | None = None

    try:
        # Save and validate uploaded file
        file_path, secure_filename = save_uploaded_file(file)

        # Compute original file hash
        original_hash = compute_sha256(file_path)

        # Extract metadata
        metadata = extract_metadata(file_path)

        # Assess risk
        risk_assessment = assess_risk(metadata)
        risk_level = risk_assessment["risk_level"]

        # Scrub metadata regardless of risk level
        scrubbed_file_path, scrub_result = scrub_metadata(file_path, risk_level)
        scrubbed_hash = compute_sha256(scrubbed_file_path)

        secure_download_name = _register_scrubbed_file(scrubbed_file_path)

        # Security logging
        log_security_event(
            "file_scrubbed",
            ip=ip,
            file_type=metadata.get("file_type"),
            risk_level=risk_level,
            extra={
                "endpoint": "/scrub",
                "filename": file.filename,
                "scrubbed_fields": len(
                    scrub_result.get("scrubbed_fields", [])
                ),
            },
        )

        response = {
            "filename": file.filename,
            "secure_filename": secure_filename,
            "original_file_hash": original_hash,
            "risk_assessment": risk_assessment,
            "scrubbing": {
                "performed": True,
                "risk_level": risk_level,
                "scrubbed_file_hash": scrubbed_hash,
                "scrubbed_fields": scrub_result.get("scrubbed_fields", []),
                "download_url": f"/download/{secure_download_name}",
            },
        }

        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scrubbing error: {str(e)}")
    finally:
        # Cleanup original file
        if file_path:
            cleanup_file(file_path)
        # Note: scrubbed file is kept for download, will be cleaned up separately


@app.get("/download/{filename}")
async def download_file(request: Request, filename: str):
    """
    Download a scrubbed file if it is registered, unexpired, and in the temp dir.
    """
    ip = _get_client_ip(request)
    try:
        check_rate_limit(ip)
    except RateLimitError:
        log_security_event(
            "rate_limit_triggered",
            ip=ip,
            extra={"endpoint": "/download"},
        )
        raise HTTPException(status_code=429, detail="Too Many Requests")

    try:
        # Clean up expired files before processing this request
        _cleanup_expired_files()

        # Security: validate filename does not contain path traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")

        # Only allow previously registered scrubbed filenames
        created_at = SCRUBBED_FILES.get(filename)
        if created_at is None or _is_expired(created_at):
            # Ensure expired entries are cleaned up
            SCRUBBED_FILES.pop(filename, None)
            raise HTTPException(status_code=404, detail="File not found or expired")

        temp_dir = Path(tempfile.gettempdir()) / "metaguard"
        file_path = temp_dir / filename

        if not file_path.exists():
            SCRUBBED_FILES.pop(filename, None)
            raise HTTPException(status_code=404, detail="File not found or expired")

        # Verify file is in temp directory (prevent path traversal)
        if not str(file_path.resolve()).startswith(str(temp_dir.resolve())):
            raise HTTPException(status_code=403, detail="Access denied")

        # Security logging
        log_security_event(
            "file_downloaded",
            ip=ip,
            extra={
                "endpoint": "/download",
                "filename": filename,
            },
        )

        return FileResponse(
            path=str(file_path),
            filename=filename.replace("_scrubbed", ""),
            media_type="application/octet-stream",
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download error: {str(e)}")


@app.on_event("shutdown")
async def cleanup_temp_files() -> None:
    """Cleanup temporary files on shutdown, including expired scrubbed files."""
    _cleanup_expired_files()
    temp_dir = Path(tempfile.gettempdir()) / "metaguard"
    if temp_dir.exists():
        try:
            for file in temp_dir.iterdir():
                if file.is_file():
                    cleanup_file(str(file))
        except Exception:
            # Swallow cleanup errors; they are non-fatal.
            pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
