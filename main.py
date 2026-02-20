"""
MetaGuard - FastAPI application for metadata analysis and scrubbing.
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from file_validation import save_uploaded_file, cleanup_file
from analyzer import extract_metadata, compute_sha256
from risk_engine import assess_risk
from scrubber import scrub_metadata


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


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "MetaGuard",
        "version": "1.0.0",
        "description": "Metadata analysis and scrubbing service",
        "endpoints": {
            "/analyze": "POST - Analyze metadata and calculate risk score",
            "/scrub": "POST - Scrub metadata from files with Medium/High risk",
            "/health": "GET - Health check endpoint"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Analyze uploaded file and extract metadata with risk assessment.
    
    Args:
        file: Uploaded file (image, PDF, or DOCX)
        
    Returns:
        JSON response with metadata, risk score, and risk level
    """
    file_path = None
    try:
        # Save and validate uploaded file
        file_path, secure_filename = save_uploaded_file(file)
        
        # Compute original file hash
        original_hash = compute_sha256(file_path)
        
        # Extract metadata
        metadata = extract_metadata(file_path)
        
        # Assess risk
        risk_assessment = assess_risk(metadata)
        
        # Prepare response
        response = {
            "filename": file.filename,
            "secure_filename": secure_filename,
            "original_file_hash": original_hash,
            "metadata": metadata,
            "risk_assessment": risk_assessment
        }
        
        return JSONResponse(content=response)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    finally:
        # Cleanup original file
        if file_path:
            cleanup_file(file_path)


@app.post("/scrub")
async def scrub_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Scrub metadata from uploaded file if risk level is Medium or High.
    
    Args:
        file: Uploaded file (image, PDF, or DOCX)
        
    Returns:
        JSON response with scrubbing results and scrubbed file download
    """
    file_path = None
    scrubbed_file_path = None
    
    try:
        # Save and validate uploaded file
        file_path, secure_filename = save_uploaded_file(file)
        
        # Compute original file hash
        original_hash = compute_sha256(file_path)
        
        # Extract metadata
        metadata = extract_metadata(file_path)
        
        # Assess risk
        risk_assessment = assess_risk(metadata)
        risk_level = risk_assessment['risk_level']
        
        # Scrub if Medium or High risk
        if risk_level in ['Medium', 'High']:
            scrubbed_file_path, scrub_result = scrub_metadata(file_path, risk_level)
            scrubbed_hash = compute_sha256(scrubbed_file_path)
            
            response = {
                "filename": file.filename,
                "secure_filename": secure_filename,
                "original_file_hash": original_hash,
                "risk_assessment": risk_assessment,
                "scrubbing": {
                    "performed": True,
                    "risk_level": risk_level,
                    "scrubbed_file_hash": scrubbed_hash,
                    "scrubbed_fields": scrub_result.get('scrubbed_fields', []),
                    "download_url": f"/download/{Path(scrubbed_file_path).name}"
                }
            }
        else:
            # Low risk - no scrubbing needed
            response = {
                "filename": file.filename,
                "secure_filename": secure_filename,
                "original_file_hash": original_hash,
                "risk_assessment": risk_assessment,
                "scrubbing": {
                    "performed": False,
                    "reason": f"Risk level is {risk_level}. Scrubbing only performed for Medium and High risk files."
                }
            }
        
        return JSONResponse(content=response)
        
    except ValueError as e:
        # Low risk file - no scrubbing needed
        if file_path:
            cleanup_file(file_path)
        raise HTTPException(status_code=400, detail=str(e))
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
async def download_file(filename: str):
    """
    Download scrubbed file.
    
    Args:
        filename: Secure filename of the scrubbed file
        
    Returns:
        File download response
    """
    try:
        # Security: validate filename doesn't contain path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        temp_dir = Path(tempfile.gettempdir()) / "metaguard"
        file_path = temp_dir / filename
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Verify file is in temp directory (prevent path traversal)
        if not str(file_path).startswith(str(temp_dir)):
            raise HTTPException(status_code=403, detail="Access denied")
        
        return FileResponse(
            path=str(file_path),
            filename=filename.replace('_scrubbed', ''),
            media_type='application/octet-stream'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download error: {str(e)}")


@app.on_event("shutdown")
async def cleanup_temp_files():
    """Cleanup temporary files on shutdown."""
    temp_dir = Path(tempfile.gettempdir()) / "metaguard"
    if temp_dir.exists():
        try:
            for file in temp_dir.iterdir():
                if file.is_file():
                    cleanup_file(str(file))
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
