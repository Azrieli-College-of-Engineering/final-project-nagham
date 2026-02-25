"""
File validation module for secure file handling.
Validates MIME types, file extensions, and file sizes.
"""

import os
import secrets
import tempfile
from pathlib import Path
from typing import Tuple, Optional
import magic
from fastapi import UploadFile, HTTPException


# Allowed file types
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.pdf', '.docx'}
ALLOWED_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff',
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes


class FileValidationError(Exception):
    """Custom exception for file validation errors."""
    pass


def validate_file_extension(filename: str) -> None:
    """
    Validate file extension against whitelist.
    
    Args:
        filename: Name of the uploaded file
        
    Raises:
        FileValidationError: If extension is not allowed
    """
    file_ext = Path(filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise FileValidationError(
            f"File extension '{file_ext}' is not allowed. "
            f"Allowed extensions: {', '.join(ALLOWED_EXTENSIONS)}"
        )


def validate_mime_type(file_content: bytes, filename: str) -> None:
    """
    Validate MIME type using python-magic.
    
    Args:
        file_content: Raw file content
        filename: Original filename
        
    Raises:
        FileValidationError: If MIME type is not allowed
    """
    try:
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_buffer(file_content)
    except Exception as e:
        raise FileValidationError(f"Unable to detect MIME type: {str(e)}")
    
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise FileValidationError(
            f"MIME type '{detected_mime}' is not allowed. "
            f"Allowed types: {', '.join(ALLOWED_MIME_TYPES)}"
        )
    
    # Additional check: ensure MIME type matches extension
    file_ext = Path(filename).suffix.lower()
    mime_to_ext = {
        'image/jpeg': {'.jpg', '.jpeg'},
        'image/png': {'.png'},
        'image/gif': {'.gif'},
        'image/bmp': {'.bmp'},
        'image/tiff': {'.tiff'},
        'application/pdf': {'.pdf'},
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': {'.docx'}
    }
    
    expected_exts = mime_to_ext.get(detected_mime, set())
    if expected_exts and file_ext not in expected_exts:
        raise FileValidationError(
            f"MIME type '{detected_mime}' does not match file extension '{file_ext}'"
        )


def validate_file_size(file_content: bytes) -> None:
    """
    Validate file size against maximum limit.
    
    Args:
        file_content: Raw file content
        
    Raises:
        FileValidationError: If file exceeds size limit
    """
    file_size = len(file_content)
    if file_size > MAX_FILE_SIZE:
        raise FileValidationError(
            f"File size {file_size} bytes exceeds maximum limit of {MAX_FILE_SIZE} bytes"
        )
    if file_size == 0:
        raise FileValidationError("File is empty")


def generate_secure_filename(original_filename: str) -> str:
    """
    Generate a secure random filename to prevent path traversal and reuse.
    
    Args:
        original_filename: Original filename from upload
        
    Returns:
        Secure random filename with original extension
    """
    ext = Path(original_filename).suffix.lower()
    random_name = secrets.token_urlsafe(32)
    return f"{random_name}{ext}"


def save_uploaded_file(upload_file: UploadFile) -> Tuple[str, str]:
    """
    Securely save uploaded file to temporary directory.
    
    Args:
        upload_file: FastAPI UploadFile object
        
    Returns:
        Tuple of (file_path, secure_filename)
        
    Raises:
        FileValidationError: If validation fails
        HTTPException: If file handling fails
    """
    try:
        # Read file content
        file_content = upload_file.file.read()
        
        # Validate file size
        validate_file_size(file_content)
        
        # Validate file extension
        validate_file_extension(upload_file.filename)
        
        # Validate MIME type
        validate_mime_type(file_content, upload_file.filename)
        
        # Generate secure filename
        secure_filename = generate_secure_filename(upload_file.filename)
        
        # Create temporary directory if it doesn't exist
        temp_dir = Path(tempfile.gettempdir()) / "metaguard"
        temp_dir.mkdir(exist_ok=True, mode=0o700)
        
        # Save file with secure filename
        file_path = temp_dir / secure_filename
        
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        # Set restrictive permissions
        os.chmod(file_path, 0o600)
        
        return str(file_path), secure_filename
        
    except FileValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File handling error: {str(e)}")


def cleanup_file(file_path: str) -> None:
    """
    Safely delete a file after processing.
    
    Args:
        file_path: Path to file to delete
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        # Silently fail on cleanup errors
        pass
