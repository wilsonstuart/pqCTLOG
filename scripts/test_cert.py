#!/usr/bin/env python3
"""
Test script for certificate parsing functionality.
"""
import sys
import logging
import os
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ctlog.simplified_crtsh_client import SimplifiedCRTshClient

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('test_cert')

def test_cert_parsing(cert_id):
    """Test parsing a specific certificate by ID."""
    client = SimplifiedCRTshClient()
    logger.info(f"Testing certificate ID: {cert_id}")
    
    # Try to get certificate details
    details = client._get_certificate_details(cert_id)
    if details:
        logger.info("Successfully parsed certificate:")
        logger.info(f"  Subject: {details.get('subject', {}).get('CN', 'Unknown')}")
        logger.info(f"  Issuer: {details.get('issuer', {}).get('CN', 'Unknown')}")
        logger.info(f"  Public Key: {details.get('public_key', {}).get('algorithm', 'Unknown')}")
        logger.info(f"  Signature Algorithm: {details.get('signature_algorithm', {}).get('full_name', 'Unknown')}")
        logger.info(f"  Valid From: {details.get('not_before', 'Unknown')}")
        logger.info(f"  Valid Until: {details.get('not_after', 'Unknown')}")
    else:
        logger.error("Failed to parse certificate")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <certificate_id>")
        sys.exit(1)
    
    try:
        cert_id = int(sys.argv[1])
        test_cert_parsing(cert_id)
    except ValueError:
        logger.error("Certificate ID must be an integer")
        sys.exit(1)
