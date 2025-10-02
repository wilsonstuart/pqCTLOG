"""
Tests for utility functions.
"""
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

from src.core.utils import safe_parse_date, validate_domain, sanitize_filename


class TestSafeParsDate:
    """Test date parsing utility."""
    
    def test_parse_iso_format(self):
        """Test parsing ISO format dates."""
        date_str = "2023-01-01T12:00:00"
        result = safe_parse_date(date_str)
        
        assert result is not None
        assert result.year == 2023
        assert result.month == 1
        assert result.day == 1
    
    def test_parse_iso_with_z(self):
        """Test parsing ISO format with Z suffix."""
        date_str = "2023-01-01T12:00:00Z"
        result = safe_parse_date(date_str)
        
        assert result is not None
        assert result.year == 2023
    
    def test_parse_datetime_object(self):
        """Test passing datetime object."""
        dt = datetime(2023, 1, 1, 12, 0, 0)
        result = safe_parse_date(dt)
        
        assert result is dt
    
    def test_parse_none(self):
        """Test parsing None value."""
        result = safe_parse_date(None)
        assert result is None
    
    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = safe_parse_date("")
        assert result is None
    
    def test_parse_invalid_format(self):
        """Test parsing invalid date format."""
        result = safe_parse_date("invalid date")
        assert result is None


class TestValidateDomain:
    """Test domain validation utility."""
    
    def test_valid_domain(self):
        """Test valid domain names."""
        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("test-domain.co.uk") is True
    
    def test_invalid_domain(self):
        """Test invalid domain names."""
        assert validate_domain("") is False
        assert validate_domain("invalid..domain") is False
        assert validate_domain("domain-") is False
        assert validate_domain("-domain") is False
    
    def test_domain_too_long(self):
        """Test domain name that's too long."""
        long_domain = "a" * 254 + ".com"
        assert validate_domain(long_domain) is False


class TestSanitizeFilename:
    """Test filename sanitization utility."""
    
    def test_remove_invalid_chars(self):
        """Test removal of invalid characters."""
        filename = 'test<>:"/\\|?*file.txt'
        result = sanitize_filename(filename)
        
        assert '<' not in result
        assert '>' not in result
        assert ':' not in result
        assert '"' not in result
        assert '/' not in result
        assert '\\' not in result
        assert '|' not in result
        assert '?' not in result
        assert '*' not in result
    
    def test_trim_dots_spaces(self):
        """Test trimming dots and spaces."""
        filename = "  .test file.  "
        result = sanitize_filename(filename)
        
        assert not result.startswith(' ')
        assert not result.endswith(' ')
        assert not result.startswith('.')
        assert not result.endswith('.')
    
    def test_length_limit(self):
        """Test filename length limiting."""
        long_filename = "a" * 300 + ".txt"
        result = sanitize_filename(long_filename)
        
        assert len(result) <= 255
    
    def test_empty_filename(self):
        """Test handling empty filename."""
        result = sanitize_filename("")
        assert result == "unnamed"