"""
Storage module for persisting certificate and scan results.
"""
from .opensearch_client import OpenSearchClient
from .models import CertificateDocument, ScanResultDocument

__all__ = [
    'OpenSearchClient',
    'CertificateDocument',
    'ScanResultDocument'
]
