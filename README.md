# MetaGuard

MetaGuard is a FastAPI-based web application for analyzing and scrubbing metadata from images, PDFs, and DOCX files. It provides risk assessment based on metadata content and can automatically remove sensitive information.

## Features

- **Metadata Extraction**: Extract metadata from images (JPEG, PNG, GIF, BMP, TIFF), PDFs, and DOCX files
- **Risk Scoring**: Rule-based risk assessment system that scores metadata based on sensitivity
- **Metadata Scrubbing**: Remove metadata from all files regardless of risk level
- **Secure File Handling**: 
  - MIME type validation
  - File size limits (10MB max)
  - Secure random filenames
  - Automatic cleanup
- **SHA-256 Hashing**: Compute file hashes before and after scrubbing

## Risk Scoring System

The risk scoring system assigns points based on detected metadata:

- **GPS coordinates**: +40 points
- **Author email**: +30 points
- **Username**: +20 points
- **Software version**: +15 points
- **Camera model**: +5 points
- **Camera make**: +5 points

Risk levels:
- **Low**: 0-29 points
- **Medium**: 30-69 points
- **High**: 70-100 points

## Installation

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

2. Install system dependencies for `python-magic`:

**macOS:**
```bash
brew install libmagic
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libmagic1
```

**Windows:**
Download from [file for Windows](https://github.com/pidydx/libmagicwin64) or use alternative MIME detection.

3. Run the application:

```bash
python3 main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## Getting Started - Interactive UI Guide

MetaGuard provides an interactive web interface for easy testing and usage. When you start the server, navigate to:

**http://localhost:8000/docs**

This opens the FastAPI interactive documentation (Swagger UI) where you can test all operations directly from your browser.

### Available Operations

The UI displays three main operations you can perform:

1. **`POST /analyze`** - Analyze file metadata and get risk assessment
2. **`POST /verify`** - Check if a file contains high-risk metadata (without scrubbing)
3. **`POST /scrub`** - Remove metadata from files and get a download link

### How to Use the Interactive UI

#### Step 1: Access the Documentation
- Open your browser and go to `http://localhost:8000/docs`
- You'll see a list of available endpoints with descriptions

#### Step 2: Select an Operation
- Click on any endpoint (e.g., `/analyze`, `/scrub`, or `/verify`) to expand its details
- Read the endpoint description and parameters

#### Step 3: Try It Out
- Click the **"Try it out"** button in the expanded endpoint section
- This enables the request form

#### Step 4: Upload a File
- Click **"Choose File"** next to the `file` parameter
- Select an image (`.jpg`, `.png`, etc.), PDF (`.pdf`), or DOCX (`.docx`) file from your computer
- Ensure the file is under 10MB

#### Step 5: Execute the Request
- Click the **"Execute"** button
- The response will appear below, showing:
  - Extracted metadata
  - Risk score and risk level
  - File hash
  - (For `/scrub`) Download URL for the scrubbed file

### Downloading Scrubbed Files

After using the `/scrub` endpoint:

1. **Get the Download URL**: The response includes a `download_url` field, e.g., `/download/random_token_scrubbed.jpg`

2. **Download the File**: You have two options:

   **Option A: Using the Browser**
   - Copy the download URL from the response
   - Append it to your base URL: `http://localhost:8000/download/random_token_scrubbed.jpg`
   - Paste this URL in your browser's address bar and press Enter
   - The file will download automatically

   **Option B: Using curl**
   ```bash
   curl -X GET "http://localhost:8000/download/random_token_scrubbed.jpg" \
     -o scrubbed_file.jpg
   ```

3. **Important Notes**:
   - Scrubbed files expire after **5 minutes**
   - After expiration, the download URL returns a 404 error
   - If expired, re-run `/scrub` to generate a new scrubbed file

### Example Workflow

1. **Analyze a file first** (`/analyze`):
   - Upload your file
   - Review the metadata and risk score
   - Decide if scrubbing is needed

2. **Verify high-risk metadata** (`/verify`):
   - Quick check to see if file has high-risk metadata
   - Returns `true`/`false` for high-risk status
   - No file modification

3. **Scrub metadata** (`/scrub`):
   - Upload your file
   - Get scrubbed file with download URL
   - Download within 5 minutes

### UI Features

- **Request/Response Examples**: Each endpoint shows example request and response formats
- **Schema Documentation**: Click "Schema" to see detailed parameter descriptions
- **Try Multiple Files**: Test different file types to see how metadata varies
- **Real-time Testing**: No need for command-line tools - everything works in the browser

## API Endpoints

### GET `/`
Root endpoint with API information.

### GET `/health`
Health check endpoint.

### POST `/analyze`
Analyze uploaded file and extract metadata with risk assessment.

**Request:**
- `file`: Multipart file upload (image, PDF, or DOCX)

**Response:**
```json
{
  "filename": "example.jpg",
  "secure_filename": "random_token.jpg",
  "original_file_hash": "sha256_hash",
  "metadata": {
    "file_hash": "...",
    "file_type": ".jpg",
    "camera_model": "...",
    "gps_coordinates": {...}
  },
  "risk_assessment": {
    "risk_score": 45,
    "risk_level": "Medium",
    "score_breakdown": {
      "gps_coordinates": 40,
      "camera_model": 5
    }
  }
}
```

### POST `/scrub`
Scrub metadata from uploaded file regardless of risk level. All files are scrubbed to remove unnecessary metadata.

**Request:**
- `file`: Multipart file upload (image, PDF, or DOCX)

**Response:**
```json
{
  "filename": "example.jpg",
  "secure_filename": "random_token.jpg",
  "original_file_hash": "sha256_hash",
  "risk_assessment": {
    "risk_score": 45,
    "risk_level": "Medium",
    "score_breakdown": {...}
  },
  "scrubbing": {
    "performed": true,
    "risk_level": "Medium",
    "scrubbed_file_hash": "sha256_hash",
    "scrubbed_fields": ["GPSInfo", "DateTime"],
    "download_url": "/download/random_token_scrubbed.jpg"
  }
}
```

### GET `/download/{filename}`
Download scrubbed file.

### POST `/verify`
Analyze an uploaded file and report whether it contains **high-risk** metadata without scrubbing or modifying the file.

**Request:**
- `file`: Multipart file upload (image, PDF, or DOCX)

**Response:**
```json
{
  "filename": "example.jpg",
  "secure_filename": "random_token.jpg",
  "original_file_hash": "sha256_hash",
  "high_risk_metadata": true,
  "risk_assessment": {
    "risk_score": 80,
    "risk_level": "High",
    "score_breakdown": {...}
  }
}
```

## Example curl Commands

### Analyze an image file:

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/your/image.jpg"
```

### Analyze a PDF file:

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/your/document.pdf"
```

### Analyze a DOCX file:

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/your/document.docx"
```

### Scrub metadata from a file:

```bash
curl -X POST "http://localhost:8000/scrub" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/your/image.jpg"
```

### Download scrubbed file:

After scrubbing, use the `download_url` from the response:

```bash
curl -X GET "http://localhost:8000/download/random_token_scrubbed.jpg" \
  -o scrubbed_file.jpg
```

### Health check:

```bash
curl -X GET "http://localhost:8000/health"
```

### Verify high-risk metadata without scrubbing:

```bash
curl -X POST "http://localhost:8000/verify" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/your/image.jpg"
```

## Security Features

- **File Extension Whitelist**: Only allowed extensions are accepted
- **MIME Type Validation**: Files are validated using python-magic
- **File Size Limits**: Maximum 10MB file size
- **Secure Filenames**: Random token-based filenames prevent path traversal
- **No Path Exposure**: File paths are never returned to clients
- **Automatic Cleanup**: Files are automatically deleted after processing
- **Path Traversal Protection**: Download endpoint validates filenames

## Threat Model

MetaGuard focuses on preventing **metadata-based privacy leakage**:

- **GPS exposure**: Embedded GPS coordinates in images can reveal sensitive locations such as homes, workplaces, or secure facilities.
- **Author email exposure**: Document authorship metadata can leak personal or corporate email addresses, facilitating phishing or targeted attacks.
- **Username leakage**: Usernames and account identifiers in document metadata can expose internal user IDs or directory structures.
- **Software version fingerprinting**: Producer/creator fields and version strings can reveal exact software versions, which attackers may use to target known vulnerabilities.

The application assumes:
- Files may be malicious or malformed.
- Clients are untrusted and may attempt to bypass validation or download unauthorized files.

## Security Hardening

MetaGuard includes multiple hardening layers:

- **Rate limiting**: Per-IP rate limiting (20 requests/minute) for `/analyze`, `/scrub`, and `/download/{filename}` to reduce abuse and brute-force attempts.
- **Download expiration**: Scrubbed files are registered and available for secure download only for **5 minutes**, after which they are deleted and return HTTP 404.
- **Structured logging**: Security events (`file_analyzed`, `file_scrubbed`, `file_downloaded`, `rate_limit_triggered`) are logged as JSON with masked IPs and without raw metadata, GPS coordinates, or file paths.
- **Input validation**: File extension whitelist, MIME-type verification, and strict filename checks to block path traversal and unsupported file types.
- **File size restrictions**: Maximum file size of **10MB** to mitigate resource exhaustion and denial-of-service scenarios.

## Project Structure

```
metaguard/
├── main.py              # FastAPI application entry point
├── analyzer.py          # Metadata extraction module
├── scrubber.py          # Metadata scrubbing module
├── risk_engine.py       # Risk scoring engine
├── file_validation.py   # File validation and security
├── rate_limiter.py      # In-memory per-IP rate limiting
├── security_logging.py  # Structured security logging utilities
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## Architecture

The application follows clean architecture principles with clear separation of concerns:

- **file_validation.py**: Handles all file validation, security checks, and secure file storage
- **analyzer.py**: Responsible for metadata extraction from different file types
- **risk_engine.py**: Implements the rule-based risk scoring system
- **scrubber.py**: Handles metadata removal from files
- **main.py**: FastAPI application with REST endpoints

## Design Tradeoffs

MetaGuard makes several deliberate architectural choices that balance simplicity, security, and operational requirements:

### In-Memory Rate Limiting vs. Redis

**Choice**: In-memory rate limiting using Python dictionaries and deques.

**Rationale**:
- **Zero external dependencies**: Eliminates Redis setup, network overhead, and potential failure points.
- **Low latency**: No network round-trip for rate limit checks, critical for high-throughput scenarios.
- **Simplicity**: Easier to deploy, test, and understand for small-to-medium scale deployments.
- **Tradeoff**: Rate limits reset on application restart and don't persist across multiple server instances. Suitable for single-instance deployments or when per-instance limits are acceptable.

### Stateless Architecture (No Database)

**Choice**: No persistent database; all state is in-memory or temporary files.

**Rationale**:
- **Privacy-first**: No persistent storage of user files or metadata reduces data breach risk and compliance burden.
- **Simplicity**: Eliminates database migrations, connection pooling, and backup complexity.
- **Stateless scaling**: Each request is independent, making horizontal scaling straightforward.
- **Tradeoff**: No audit trail persistence, analytics, or cross-request state. Suitable for privacy-sensitive use cases where ephemeral processing is preferred.

### 5-Minute TTL for Scrubbed Files

**Choice**: Scrubbed files expire and are deleted after 5 minutes.

**Rationale**:
- **Security**: Limits exposure window for scrubbed files stored on disk.
- **Storage efficiency**: Prevents disk space exhaustion from abandoned downloads.
- **Privacy**: Ensures files don't persist longer than necessary for legitimate use.
- **Tradeoff**: Users must download within 5 minutes. This balances security with usability for typical workflows where immediate download is expected.

### Rule-Based Risk Engine vs. Machine Learning

**Choice**: Deterministic rule-based scoring system instead of ML models.

**Rationale**:
- **Transparency**: Rules are explicit, auditable, and explainable—critical for security tools.
- **Deterministic**: Same input always produces same output, enabling reproducible risk assessment.
- **No training data**: Avoids privacy concerns of collecting sensitive metadata for training.
- **Low latency**: Rule evaluation is fast and predictable without model inference overhead.
- **Maintainability**: Rules can be updated based on threat intelligence without retraining.
- **Tradeoff**: Less adaptive to novel attack patterns compared to ML. However, metadata risk patterns are well-understood, making rules effective and sufficient.

### File-Based Temporary Storage vs. In-Memory Processing

**Choice**: Use temporary files on disk instead of fully in-memory processing.

**Rationale**:
- **Library compatibility**: Many metadata libraries (Pillow, PyPDF2, python-docx) expect file paths rather than byte streams.
- **Memory safety**: Avoids loading large files entirely into memory, reducing memory pressure and OOM risk.
- **Predictable cleanup**: Temporary directory with TTL-based deletion simplifies lifecycle management and prevents resource leaks.
- **Tradeoff**: Disk I/O overhead compared to pure in-memory processing. Acceptable for files ≤10MB where I/O latency is minimal relative to metadata extraction time.

## Limitations

MetaGuard has the following operational and functional limitations:

- **Rate limiting synchronization**: Rate limiting is per-instance and does not synchronize across multiple application nodes. In multi-instance deployments, each instance maintains independent rate limit counters.
- **In-memory state persistence**: In-memory state (rate limits and scrubbed file registry) resets on application restart. No persistent state is maintained between restarts.
- **Audit log retention**: No persistent audit log storage—structured logs are emitted but not retained long-term. Log aggregation and retention must be handled by external logging infrastructure.
- **Scrubbed file expiration**: Scrubbed files expire after 5 minutes; delayed downloads require re-processing the original file through the `/scrub` endpoint.
- **File size constraints**: Maximum file size is 10MB to mitigate memory exhaustion and denial-of-service risks. Larger files are rejected at the validation layer.
- **Risk detection coverage**: Rule-based risk engine may not detect novel or unconventional metadata-based threats that don't match established patterns. Regular rule updates based on threat intelligence are recommended.

## License

This project is provided as-is for educational and security purposes.
