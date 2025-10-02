"""
Tests for certificate parsing functionality.
"""
import pytest
from unittest.mock import patch, MagicMock

from src.core.certificate_parser import CertificateParser, parse_certificate_pem


class TestCertificateParser:
    """Test certificate parser functionality."""
    
    def test_init_with_crypto_available(self):
        """Test parser initialization when cryptography is available."""
        with patch('src.core.certificate_parser.importlib.util.find_spec', return_value=True):
            parser = CertificateParser()
            assert parser.crypto_available is True
    
    def test_init_without_crypto(self):
        """Test parser initialization when cryptography is not available."""
        with patch('src.core.certificate_parser.importlib.util.find_spec', side_effect=ImportError):
            parser = CertificateParser()
            assert parser.crypto_available is False
    
    def test_parse_invalid_pem(self):
        """Test parsing invalid PEM data."""
        parser = CertificateParser()
        result = parser.parse_certificate_pem("invalid pem data")
        assert result is None
    
    def test_clean_pem_data(self):
        """Test PEM data cleaning."""
        parser = CertificateParser()
        
        # Test adding missing headers
        pem_data = "MIIBkTCB+wIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw=="
        cleaned = parser._clean_pem_data(pem_data)
        
        assert cleaned.startswith("-----BEGIN CERTIFICATE-----")
        assert cleaned.endswith("-----END CERTIFICATE-----")
    
    def test_parse_name_mapping(self):
        """Test DN component mapping."""
        parser = CertificateParser()
        
        # Mock OpenSSL name object
        mock_name = MagicMock()
        mock_name.get_components.return_value = [
            (b'CN', b'example.com'),
            (b'O', b'Example Org'),
            (b'C', b'US')
        ]
        
        result = parser._parse_name_openssl(mock_name)
        
        assert result['commonName'] == 'example.com'
        assert result['organizationName'] == 'Example Org'
        assert result['countryName'] == 'US'
    
    @patch('src.core.certificate_parser.certificate_parser')
    def test_global_parse_function(self, mock_parser):
        """Test global parse function."""
        mock_parser.parse_certificate_pem.return_value = {'test': 'data'}
        
        result = parse_certificate_pem("test pem", 123)
        
        mock_parser.parse_certificate_pem.assert_called_once_with("test pem", 123)
        assert result == {'test': 'data'}