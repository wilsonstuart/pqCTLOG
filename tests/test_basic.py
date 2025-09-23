"""
Basic tests for the pqCTLOG application.
"""
import unittest
from unittest.mock import patch, MagicMock

from ctlog.client import CTLogClient
from scanner.scanner import TLSScanner
from storage.opensearch_client import OpenSearchClient

def test_ct_log_client_initialization():
    """Test that CTLogClient can be initialized."""
    client = CTLogClient("https://example.com/ct/v1/")
    assert client is not None

def test_tls_scanner_initialization():
    """Test that TLSScanner can be initialized."""
    scanner = TLSScanner()
    assert scanner is not None

@patch('opensearchpy.OpenSearch')
def test_opensearch_client_initialization(mock_opensearch):
    """Test that OpenSearchClient can be initialized."""
    # Configure the mock
    mock_client = MagicMock()
    mock_opensearch.return_value = mock_client
    
    # Test with default config
    client = OpenSearchClient()
    assert client is not None
    
    # Test with custom config
    config = {
        'host': 'localhost',
        'port': 9200,
        'use_ssl': False,
        'verify_certs': False,
        'http_auth': {'username': 'admin', 'password': 'admin'},
        'index_prefix': 'test_'
    }
    client = OpenSearchClient(config=config)
    assert client is not None

def test_extract_domains_from_certificates():
    """Test domain extraction from certificates."""
    scanner = TLSScanner()
    
    # Test with empty list
    assert len(scanner.extract_domains_from_certificates([])) == 0
    
    # Test with a simple certificate
    certs = [
        {
            'subject': {'commonName': 'example.com'},
            'subject_alternative_names': ['www.example.com', 'mail.example.com']
        }
    ]
    domains = scanner.extract_domains_from_certificates(certs)
    assert 'example.com' in domains
    assert 'www.example.com' in domains
    assert 'mail.example.com' in domains

if __name__ == '__main__':
    test_ct_log_client_initialization()
    test_tls_scanner_initialization()
    test_opensearch_client_initialization()
    test_extract_domains_from_certificates()
    print("All tests passed!")
