"""
Common utility functions.
"""
import logging
from datetime import datetime
from typing import Optional, Union


def safe_parse_date(date_str: Union[str, datetime, None]) -> Optional[datetime]:
    """Safely parse a date string with multiple formats."""
    if not date_str:
        return None
    
    if isinstance(date_str, datetime):
        return date_str
        
    if not isinstance(date_str, str):
        return None
    
    formats = [
        '%Y-%m-%dT%H:%M:%S',        # ISO format
        '%Y-%m-%dT%H:%M:%SZ',       # ISO format with Z
        '%Y-%m-%dT%H:%M:%S.%f',     # ISO format with microseconds
        '%Y-%m-%dT%H:%M:%S.%fZ',    # ISO format with microseconds and Z
        '%Y-%m-%d %H:%M:%S',        # SQL format
        '%Y%m%d%H%M%SZ',            # ASN.1 UTC Time
        '%Y%m%d%H%M%S%z',           # ASN.1 GeneralizedTime
        '%Y-%m-%d'                  # Just date
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except (ValueError, TypeError):
            continue
    
    logging.getLogger(__name__).warning(f"Could not parse date string: {date_str}")
    return None


def setup_logging(config) -> None:
    """Set up logging configuration."""
    import sys
    
    log_level = getattr(logging, config.logging.level)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
    
    # Set specific log levels for noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('opensearch').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    import re
    
    if not domain or len(domain) > 253:
        return False
    
    # Basic domain validation regex
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain))


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    import re
    
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename or 'unnamed'