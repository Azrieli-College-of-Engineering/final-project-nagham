"""
Metadata extraction module.
Extracts metadata from images, PDFs, and DOCX files.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
from docx import Document
import zipfile


def compute_sha256(file_path: str) -> str:
    """
    Compute SHA-256 hash of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        SHA-256 hash as hexadecimal string
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def extract_gps_data(exif_data: Dict) -> Optional[Dict[str, float]]:
    """
    Extract GPS coordinates from EXIF data.
    
    Args:
        exif_data: EXIF data dictionary
        
    Returns:
        Dictionary with 'latitude' and 'longitude' or None
    """
    if 'GPSInfo' not in exif_data:
        return None
    
    gps_info = exif_data['GPSInfo']
    gps_data = {}
    
    for key, value in gps_info.items():
        tag = GPSTAGS.get(key, key)
        gps_data[tag] = value
    
    if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
        lat = gps_data['GPSLatitude']
        lon = gps_data['GPSLongitude']
        lat_ref = gps_data.get('GPSLatitudeRef', 'N')
        lon_ref = gps_data.get('GPSLongitudeRef', 'E')
        
        # Convert to decimal degrees
        latitude = float(lat[0]) + float(lat[1]) / 60.0 + float(lat[2]) / 3600.0
        if lat_ref == 'S':
            latitude = -latitude
        
        longitude = float(lon[0]) + float(lon[1]) / 60.0 + float(lon[2]) / 3600.0
        if lon_ref == 'W':
            longitude = -longitude
        
        return {'latitude': latitude, 'longitude': longitude}
    
    return None


def extract_image_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from image files (JPEG, PNG, etc.).
    
    Args:
        file_path: Path to image file
        
    Returns:
        Dictionary containing extracted metadata
    """
    metadata = {}
    
    try:
        with Image.open(file_path) as img:
            # Basic image info
            metadata['format'] = img.format
            metadata['mode'] = img.mode
            metadata['size'] = {'width': img.width, 'height': img.height}
            
            # EXIF data
            exif_data = {}
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = value
                
                # Extract specific fields
                if 'DateTime' in exif_data:
                    metadata['datetime'] = exif_data['DateTime']
                if 'DateTimeOriginal' in exif_data:
                    metadata['datetime_original'] = exif_data['DateTimeOriginal']
                if 'Make' in exif_data:
                    metadata['camera_make'] = exif_data['Make']
                if 'Model' in exif_data:
                    metadata['camera_model'] = exif_data['Model']
                if 'Software' in exif_data:
                    metadata['software'] = exif_data['Software']
                if 'Artist' in exif_data:
                    metadata['artist'] = exif_data['Artist']
                
                # GPS coordinates
                gps = extract_gps_data(exif_data)
                if gps:
                    metadata['gps_coordinates'] = gps
            
            # Store full EXIF if present
            if exif_data:
                metadata['exif'] = exif_data
                
    except Exception as e:
        metadata['error'] = f"Error extracting image metadata: {str(e)}"
    
    return metadata


def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from PDF files.
    
    Args:
        file_path: Path to PDF file
        
    Returns:
        Dictionary containing extracted metadata
    """
    metadata = {}
    
    try:
        with open(file_path, 'rb') as pdf_file:
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            
            # PDF info
            if pdf_reader.metadata:
                pdf_metadata = pdf_reader.metadata
                
                if '/Title' in pdf_metadata:
                    metadata['title'] = str(pdf_metadata['/Title'])
                if '/Author' in pdf_metadata:
                    metadata['author'] = str(pdf_metadata['/Author'])
                if '/Subject' in pdf_metadata:
                    metadata['subject'] = str(pdf_metadata['/Subject'])
                if '/Creator' in pdf_metadata:
                    metadata['creator'] = str(pdf_metadata['/Creator'])
                if '/Producer' in pdf_metadata:
                    metadata['producer'] = str(pdf_metadata['/Producer'])
                if '/CreationDate' in pdf_metadata:
                    metadata['creation_date'] = str(pdf_metadata['/CreationDate'])
                if '/ModDate' in pdf_metadata:
                    metadata['modification_date'] = str(pdf_metadata['/ModDate'])
                
                # Check for email in author field
                author = metadata.get('author', '')
                if '@' in author:
                    # Try to extract email
                    import re
                    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', author)
                    if email_match:
                        metadata['author_email'] = email_match.group()
            
            metadata['num_pages'] = len(pdf_reader.pages)
            
    except Exception as e:
        metadata['error'] = f"Error extracting PDF metadata: {str(e)}"
    
    return metadata


def extract_docx_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from DOCX files.
    
    Args:
        file_path: Path to DOCX file
        
    Returns:
        Dictionary containing extracted metadata
    """
    metadata = {}
    
    try:
        doc = Document(file_path)
        core_props = doc.core_properties
        
        if core_props.title:
            metadata['title'] = core_props.title
        if core_props.author:
            metadata['author'] = core_props.author
        if core_props.subject:
            metadata['subject'] = core_props.subject
        if core_props.comments:
            metadata['comments'] = core_props.comments
        if core_props.created:
            metadata['created'] = str(core_props.created)
        if core_props.modified:
            metadata['modified'] = str(core_props.modified)
        if core_props.last_modified_by:
            metadata['last_modified_by'] = core_props.last_modified_by
        if core_props.revision:
            metadata['revision'] = core_props.revision
        
        # Check for email in author field
        author = metadata.get('author', '')
        if '@' in author:
            import re
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', author)
            if email_match:
                metadata['author_email'] = email_match.group()
        
        # Extract username from last_modified_by if present
        if core_props.last_modified_by:
            metadata['username'] = core_props.last_modified_by
        
    except Exception as e:
        metadata['error'] = f"Error extracting DOCX metadata: {str(e)}"
    
    return metadata


def extract_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from a file based on its type.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary containing extracted metadata and file hash
    """
    file_ext = Path(file_path).suffix.lower()
    
    # Compute file hash
    file_hash = compute_sha256(file_path)
    
    metadata = {
        'file_hash': file_hash,
        'file_path': file_path,  # Will be removed before returning to user
        'file_type': file_ext
    }
    
    # Extract metadata based on file type
    if file_ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}:
        image_metadata = extract_image_metadata(file_path)
        metadata.update(image_metadata)
    elif file_ext == '.pdf':
        pdf_metadata = extract_pdf_metadata(file_path)
        metadata.update(pdf_metadata)
    elif file_ext == '.docx':
        docx_metadata = extract_docx_metadata(file_path)
        metadata.update(docx_metadata)
    else:
        metadata['error'] = f"Unsupported file type: {file_ext}"
    
    # Remove file_path before returning (security: don't expose paths)
    metadata.pop('file_path', None)
    
    return metadata
