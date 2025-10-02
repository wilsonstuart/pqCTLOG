"""
Tests for TLS scanner functionality.
"""
import pytest
from unittest.mock import patch, MagicMock
import ssl
import socket

from src.scanner.tls_scanner import TLSScanner
from src.core.config import AppConfig


class TestTLSScanner:
    """Test TLS scanner functionality."""
    
    def test_init(self):
        """Test TLS scanner initialization."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        assert scanner.timeout == config.tls_scanner.timeout
        assert scanner.ports == config.tls_scanner.ports
        assert scanner.tls_versions == config.tls_scanner.tls_versions
    
    def test_clean_domain_name(self):
        """Test domain name cleaning."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        # Test wildcard removal
        assert scanner._clean_domain_name('*.example.com') == 'example.com'
        
        # Test protocol removal
        assert scanner._clean_domain_name('https://example.com') == 'example.com'
        assert scanner._clean_domain_name('http://example.com') == 'example.com'
        
        # Test port removal
        assert scanner._clean_domain_name('example.com:443') == 'example.com'
        
        # Test invalid domains
        assert scanner._clean_domain_name('') is None
        assert scanner._clean_domain_name('invalid') is None
        assert scanner._clean_domain_name('a' * 300) is None
    
    def test_assess_cipher_security(self):
        """Test cipher security assessment."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        # Test insecure ciphers
        assert scanner._assess_cipher_security('RC4-MD5') == 'insecure'
        assert scanner._assess_cipher_security('DES-CBC-SHA') == 'insecure'
        assert scanner._assess_cipher_security('NULL-SHA') == 'insecure'
        
        # Test weak ciphers
        assert scanner._assess_cipher_security('3DES-EDE-CBC-SHA') == 'weak'
        assert scanner._assess_cipher_security('AES128-CBC-SHA1') == 'weak'
        
        # Test secure ciphers
        assert scanner._assess_cipher_security('TLS_AES_128_GCM_SHA256') == 'secure'
        assert scanner._assess_cipher_security('TLS_CHACHA20_POLY1305_SHA256') == 'secure'
    
    def test_is_post_quantum_cipher(self):
        """Test post-quantum cipher detection."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        # Test post-quantum ciphers
        assert scanner._is_post_quantum_cipher('KYBER_512') is True
        assert scanner._is_post_quantum_cipher('FALCON_1024') is True
        assert scanner._is_post_quantum_cipher('DILITHIUM_3') is True
        
        # Test regular ciphers
        assert scanner._is_post_quantum_cipher('TLS_AES_128_GCM_SHA256') is False
        assert scanner._is_post_quantum_cipher('ECDHE-RSA-AES256-GCM-SHA384') is False
    
    def test_analyze_security_issues(self):
        """Test security issue analysis."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        port_result = {
            'tls_versions': {
                'SSLv3': True,
                'TLSv1.0': True,
                'TLSv1.2': True
            },
            'cipher_suites': [
                {'name': 'RC4-MD5', 'security_level': 'insecure'},
                {'name': '3DES-CBC-SHA', 'security_level': 'weak'},
                {'name': 'AES128-GCM-SHA256', 'security_level': 'secure'}
            ]
        }
        
        issues = scanner._analyze_security_issues(port_result)
        
        assert 'SSLv3 supported (insecure)' in issues
        assert 'TLSv1.0 supported (deprecated)' in issues
        assert 'Insecure cipher: RC4-MD5' in issues
        assert 'Weak cipher: 3DES-CBC-SHA' in issues
    
    def test_extract_cert_info(self):
        """Test certificate information extraction."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        # Test with None
        assert scanner._extract_cert_info(None) is None
        
        # Test with mock certificate
        mock_cert = {
            'subject': [('CN', 'example.com'), ('O', 'Example Org')],
            'issuer': [('CN', 'Example CA'), ('O', 'Example CA Org')],
            'version': 3,
            'serialNumber': '12345',
            'notBefore': 'Jan 1 00:00:00 2023 GMT',
            'notAfter': 'Jan 1 00:00:00 2024 GMT',
            'subjectAltName': [('DNS', 'example.com'), ('DNS', 'www.example.com')]
        }
        
        result = scanner._extract_cert_info(mock_cert)
        
        assert result['subject']['CN'] == 'example.com'
        assert result['issuer']['CN'] == 'Example CA'
        assert result['version'] == 3
        assert result['serial_number'] == '12345'
        assert 'example.com' in result['subject_alt_names']
        assert 'www.example.com' in result['subject_alt_names']
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_test_tls_version_success(self, mock_ssl_context, mock_socket):
        """Test successful TLS version testing."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        # Mock SSL connection
        mock_ssock = MagicMock()
        mock_ssock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        mock_ssock.version.return_value = 'TLSv1.3'
        mock_ssock.getpeercert.return_value = {'subject': [('CN', 'example.com')]}
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl_context.return_value = mock_context
        
        mock_sock = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        supported, info = scanner._test_tls_version('example.com', 443, 'TLSv1.3')
        
        assert supported is True
        assert info is not None
        assert info['cipher'] == ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        assert info['version'] == 'TLSv1.3'
    
    @patch('socket.create_connection')
    def test_test_tls_version_failure(self, mock_socket):
        """Test TLS version testing failure."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        # Mock connection failure
        mock_socket.side_effect = socket.timeout("Connection timed out")
        
        supported, info = scanner._test_tls_version('example.com', 443, 'TLSv1.3')
        
        assert supported is False
        assert info is None
    
    def test_create_error_result(self):
        """Test error result creation."""
        config = AppConfig()
        scanner = TLSScanner(config)
        
        result = scanner._create_error_result('example.com', 'Connection failed')
        
        assert result['domain'] == 'example.com'
        assert result['success'] is False
        assert result['error'] == 'Connection failed'
        assert 'Scan failed: Connection failed' in result['summary']['security_issues']