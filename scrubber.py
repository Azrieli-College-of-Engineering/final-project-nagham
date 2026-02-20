"""
Metadata scrubbing module.
Removes high and medium risk metadata from files.
"""

import shutil
from pathlib import Path
from typing import Dict, Any, Tuple
from PIL import Image
from PIL.ExifTags import TAGS
import PyPDF2
from docx import Document
from analyzer import compute_sha256


def scrub_image_metadata(file_path: str, output_path: str) -> Dict[str, Any]:
    """
    Remove metadata from image files.
    
    Args:
        file_path: Path to original image file
        output_path: Path to save scrubbed image
        
    Returns:
        Dictionary with scrubbing results
    """
    result = {
        'scrubbed_fields': [],
        'success': False
    }
    
    try:
        with Image.open(file_path) as img:
            # Create a copy without EXIF data
            data = list(img.getdata())
            image_without_exif = Image.new(img.mode, img.size)
            image_without_exif.putdata(data)
            
            # Save without EXIF
            image_without_exif.save(output_path, format=img.format)
            
            # Check what was removed
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                for tag_id in exif.keys():
                    tag = TAGS.get(tag_id, tag_id)
                    result['scrubbed_fields'].append(str(tag))
            
            result['success'] = True
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def scrub_pdf_metadata(file_path: str, output_path: str) -> Dict[str, Any]:
    """
    Remove metadata from PDF files.
    
    Args:
        file_path: Path to original PDF file
        output_path: Path to save scrubbed PDF
        
    Returns:
        Dictionary with scrubbing results
    """
    result = {
        'scrubbed_fields': [],
        'success': False
    }
    
    try:
        with open(file_path, 'rb') as input_file:
            pdf_reader = PyPDF2.PdfReader(input_file)
            pdf_writer = PyPDF2.PdfWriter()
            
            # Copy all pages
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)
            
            # Remove metadata
            metadata_fields = ['/Title', '/Author', '/Subject', '/Creator', 
                             '/Producer', '/CreationDate', '/ModDate']
            
            if pdf_reader.metadata:
                for field in metadata_fields:
                    if field in pdf_reader.metadata:
                        result['scrubbed_fields'].append(field)
            
            # Write scrubbed PDF
            with open(output_path, 'wb') as output_file:
                pdf_writer.write(output_file)
            
            result['success'] = True
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def scrub_docx_metadata(file_path: str, output_path: str) -> Dict[str, Any]:
    """
    Remove metadata from DOCX files.
    
    Args:
        file_path: Path to original DOCX file
        output_path: Path to save scrubbed DOCX
        
    Returns:
        Dictionary with scrubbing results
    """
    result = {
        'scrubbed_fields': [],
        'success': False
    }
    
    try:
        doc = Document(file_path)
        core_props = doc.core_properties
        
        # Track what we're removing
        fields_to_remove = [
            'title', 'author', 'subject', 'comments',
            'last_modified_by', 'revision'
        ]
        
        for field in fields_to_remove:
            if hasattr(core_props, field):
                value = getattr(core_props, field)
                if value:
                    result['scrubbed_fields'].append(field)
                    setattr(core_props, field, None)
        
        # Save scrubbed document
        doc.save(output_path)
        
        result['success'] = True
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def scrub_metadata(file_path: str, risk_level: str) -> Tuple[str, Dict[str, Any]]:
    """
    Scrub metadata from file regardless of risk level.
    
    Args:
        file_path: Path to original file
        risk_level: Risk level ('Low', 'Medium', or 'High')
        
    Returns:
        Tuple of (scrubbed_file_path, scrubbing_results)
    """
    file_path_obj = Path(file_path)
    file_ext = file_path_obj.suffix.lower()
    output_path = str(file_path_obj.with_name(f"{file_path_obj.stem}_scrubbed{file_ext}"))
    
    result = {
        'original_file': file_path,
        'scrubbed_file': output_path,
        'risk_level': risk_level
    }
    
    # Scrub based on file type
    if file_ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}:
        scrub_result = scrub_image_metadata(file_path, output_path)
    elif file_ext == '.pdf':
        scrub_result = scrub_pdf_metadata(file_path, output_path)
    elif file_ext == '.docx':
        scrub_result = scrub_docx_metadata(file_path, output_path)
    else:
        scrub_result = {
            'success': False,
            'error': f'Unsupported file type for scrubbing: {file_ext}'
        }
    
    result.update(scrub_result)
    
    if scrub_result.get('success'):
        # Compute hash of scrubbed file
        result['scrubbed_file_hash'] = compute_sha256(output_path)
    
    return output_path, result
