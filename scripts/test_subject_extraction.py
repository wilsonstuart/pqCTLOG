#!/usr/bin/env python3
"""
Test script to verify subject and issuer extraction from certificates.
"""
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ctlog.crtsh_client import CRTshClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def create_test_certificate() -> Dict[str, Any]:
    """Create a test certificate with known subject and issuer data."""
    return {
        "id": 123456789,
        "issuer_ca_id": 16418,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "entry_timestamp": "2023-01-01T12:00:00.000000",
        "not_before": "2023-01-01T00:00:00",
        "not_after": "2023-04-01T23:59:59",
        "serial_number": "abcdef1234567890",
        "sig_alg_name": "sha256WithRSAEncryption",
        "subject_dn": "C=US, ST=California, L=San Francisco, O=Example Corp, OU=IT, CN=example.com, emailAddress=admin@example.com"
    }

def process_certificate(cert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process certificate data and extract subject and issuer information."""
    # Extract basic fields
    cert_id = str(cert_data['id'])
    common_name = cert_data.get('common_name', '')
    name_value = cert_data.get('name_value', '')
    issuer_name = cert_data.get('issuer_name', '')
    issuer_ca_id = cert_data.get('issuer_ca_id')
    
    # Parse issuer components
    issuer_components = {}
    if isinstance(issuer_name, str):
        for part in issuer_name.split(','):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                issuer_components[key.strip()] = value.strip()
    
    # Parse subject components
    subject_components = {}
    if 'subject_dn' in cert_data:
        subject_dn = cert_data['subject_dn']
        for part in subject_dn.split(','):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip().upper()
                if key in ['CN', 'O', 'OU', 'C', 'L', 'ST', 'EMAILADDRESS']:
                    subject_components[key] = value.strip()
    
    # Extract subject alternative names
    subject_alternative_names = []
    if name_value:
        names = [name.strip() for name in name_value.split('\n') if name.strip()]
        subject_alternative_names = [name for name in names if name != common_name]
    
    # Ensure we have a subject common name
    subject_common_name = subject_components.get('CN', common_name or '')
    if not subject_common_name and subject_alternative_names:
        subject_common_name = subject_alternative_names[0]
    
    # Create the certificate document
    cert_doc = {
        'id': cert_id,
        'serial_number': cert_data.get('serial_number', cert_id),
        'common_name': common_name,
        'subject_common_name': subject_common_name,
        'name_value': name_value,
        'issuer_name': issuer_name,
        'issuer_ca_id': issuer_ca_id,
        'issuer': {
            'name': issuer_name,
            'ca_id': issuer_ca_id,
            'common_name': issuer_components.get('CN', ''),
            'organization': issuer_components.get('O', ''),
            'organizational_unit': issuer_components.get('OU', ''),
            'country': issuer_components.get('C', ''),
            'locality': issuer_components.get('L', ''),
            'state': issuer_components.get('ST', ''),
            'email': issuer_components.get('EMAILADDRESS', '')
        },
        'subject': {
            'common_name': subject_common_name,
            'organization': subject_components.get('O', ''),
            'organizational_unit': subject_components.get('OU', ''),
            'country': subject_components.get('C', ''),
            'locality': subject_components.get('L', ''),
            'state': subject_components.get('ST', ''),
            'email': subject_components.get('EMAILADDRESS', '')
        },
        'subject_alternative_names': subject_alternative_names,
        'validity': {
            'not_before': cert_data.get('not_before'),
            'not_after': cert_data.get('not_after')
        },
        'signature_algorithm': cert_data.get('sig_alg_name', ''),
        'raw_data': cert_data,
        'updated_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    return cert_doc

def main():
    """Main function to test subject and issuer extraction."""
    # Create a test certificate
    test_cert = create_test_certificate()
    
    # Process the certificate
    processed = process_certificate(test_cert)
    
    # Print the results
    print("\n=== Test Certificate ===")
    print(json.dumps(test_cert, indent=2))
    
    print("\n=== Processed Certificate ===")
    print(json.dumps(processed, indent=2, default=str))
    
    # Verify the results
    print("\n=== Verification ===")
    print(f"Subject Common Name: {processed['subject_common_name']}")
    print(f"Subject Organization: {processed['subject']['organization']}")
    print(f"Subject Country: {processed['subject']['country']}")
    print(f"Issuer Common Name: {processed['issuer']['common_name']}")
    print(f"Issuer Organization: {processed['issuer']['organization']}")
    print(f"Subject Alternative Names: {processed['subject_alternative_names']}")

if __name__ == "__main__":
    import os
    main()
