# MetaGuard

MetaGuard is a FastAPI-based web application for analyzing and scrubbing metadata from images, PDFs, and DOCX files. It provides risk assessment based on metadata content and can automatically remove sensitive information.

## Features

- **Metadata Extraction**: Extract metadata from images (JPEG, PNG, GIF, BMP, TIFF), PDFs, and DOCX files
- **Risk Scoring**: Rule-based risk assessment system that scores metadata based on sensitivity
- **Metadata Scrubbing**: Automatically remove high and medium risk metadata
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
python main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

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
Scrub metadata from uploaded file if risk level is Medium or High.

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

## Limitations

- Files are stored temporarily and cleaned up after processing
- No database is used (stateless design)
- Scrubbed files are kept temporarily for download but should be cleaned up manually in production
- Maximum file size is 10MB

## License

This project is provided as-is for educational and security purposes.
