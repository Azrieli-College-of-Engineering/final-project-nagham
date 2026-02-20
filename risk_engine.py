"""
Risk scoring engine for metadata analysis.
Implements rule-based scoring system for metadata risk assessment.
"""

from typing import Dict, Any, Tuple
import re


# Risk scoring rules
RISK_RULES = {
    'gps_coordinates': 40,
    'author_email': 30,
    'username': 20,
    'software': 15,
    'camera_model': 5,
    'camera_make': 5,
    'producer': 15,  # PDF producer/software
    'creator': 15,   # PDF creator/software
    'software_version': 15,  # Generic software version
}


def detect_email_in_text(text: str) -> bool:
    """
    Detect if text contains an email address.
    
    Args:
        text: Text to search
        
    Returns:
        True if email is found, False otherwise
    """
    if not text:
        return False
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    return bool(re.search(email_pattern, str(text)))


def detect_username(text: str) -> bool:
    """
    Detect if text looks like a username.
    Common patterns: domain\\username, username@domain, etc.
    
    Args:
        text: Text to search
        
    Returns:
        True if username pattern is found, False otherwise
    """
    if not text:
        return False
    text_str = str(text).lower()
    
    # Check for domain\username pattern
    if '\\' in text_str:
        return True
    
    # Check for username@domain (but not email)
    if '@' in text_str and not detect_email_in_text(text_str):
        return True
    
    # Check for common username patterns
    username_patterns = [
        r'^[a-z0-9_-]{3,}$',  # Simple username
        r'user\s*name\s*[:=]\s*\w+',  # "username: value"
    ]
    
    for pattern in username_patterns:
        if re.search(pattern, text_str):
            return True
    
    return False


def detect_software_version(text: str) -> bool:
    """
    Detect if text contains software version information.
    
    Args:
        text: Text to search
        
    Returns:
        True if software version is detected, False otherwise
    """
    if not text:
        return False
    text_str = str(text).lower()
    
    # Common version patterns
    version_patterns = [
        r'\d+\.\d+\.\d+',  # x.y.z
        r'version\s*\d+',  # version X
        r'v\d+\.\d+',      # vX.Y
        r'\w+\s+\d+\.\d+', # Software X.Y
    ]
    
    for pattern in version_patterns:
        if re.search(pattern, text_str):
            return True
    
    return False


def calculate_risk_score(metadata: Dict[str, Any]) -> Tuple[int, Dict[str, int]]:
    """
    Calculate risk score based on metadata content.
    
    Args:
        metadata: Dictionary containing extracted metadata
        
    Returns:
        Tuple of (total_score, score_breakdown)
    """
    score = 0
    breakdown = {}
    
    # Check for GPS coordinates
    if 'gps_coordinates' in metadata:
        points = RISK_RULES['gps_coordinates']
        score += points
        breakdown['gps_coordinates'] = points
    
    # Check for author email
    if 'author_email' in metadata:
        points = RISK_RULES['author_email']
        score += points
        breakdown['author_email'] = points
    else:
        # Check if email is in author field
        author = metadata.get('author', '')
        if detect_email_in_text(author):
            points = RISK_RULES['author_email']
            score += points
            breakdown['author_email'] = points
    
    # Check for username
    if 'username' in metadata:
        points = RISK_RULES['username']
        score += points
        breakdown['username'] = points
    else:
        # Check in various fields
        for field in ['last_modified_by', 'artist', 'creator']:
            if field in metadata:
                value = metadata[field]
                if detect_username(str(value)):
                    points = RISK_RULES['username']
                    score += points
                    breakdown[f'{field}_username'] = points
                    break
    
    # Check for software version
    software_fields = ['software', 'producer', 'creator']
    software_found = False
    
    for field in software_fields:
        if field in metadata:
            value = metadata[field]
            if detect_software_version(str(value)):
                points = RISK_RULES.get(field, RISK_RULES['software_version'])
                if not software_found:  # Only count once
                    score += points
                    breakdown[f'{field}_version'] = points
                    software_found = True
                    break
    
    # Check for camera model
    if 'camera_model' in metadata:
        points = RISK_RULES['camera_model']
        score += points
        breakdown['camera_model'] = points
    
    # Check for camera make
    if 'camera_make' in metadata:
        points = RISK_RULES['camera_make']
        score += points
        breakdown['camera_make'] = points
    
    # Cap score at 100
    score = min(score, 100)
    
    return score, breakdown


def determine_risk_level(score: int) -> str:
    """
    Determine risk level based on score.
    
    Args:
        score: Risk score (0-100)
        
    Returns:
        Risk level: 'Low', 'Medium', or 'High'
    """
    if score >= 70:
        return 'High'
    elif score >= 30:
        return 'Medium'
    else:
        return 'Low'


def assess_risk(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assess risk of metadata and return comprehensive risk analysis.
    
    Args:
        metadata: Dictionary containing extracted metadata
        
    Returns:
        Dictionary containing risk score, level, and breakdown
    """
    score, breakdown = calculate_risk_score(metadata)
    risk_level = determine_risk_level(score)
    
    return {
        'risk_score': score,
        'risk_level': risk_level,
        'score_breakdown': breakdown
    }
