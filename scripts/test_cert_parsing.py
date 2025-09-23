#!/usr/bin/env python3
"""
Test script for certificate parsing functionality.
"""
import argparse
import logging
import os
import sys
from typing import Dict, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ctlog.crtsh_client import CRTshClient, CRTshError

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cert_parsing_test.log')
    ]
)
logger = logging.getLogger(__name__)

def test_cert_parsing(cert_id: int) -> Dict[str, Any]:
    """
    Test certificate parsing for a given certificate ID.
    
    Args:
        cert_id: The certificate ID to test
        
    Returns:
        Dictionary with test results
    """
    logger.info(f"Testing certificate parsing for ID: {cert_id}")
    results = {
        'success': False,
        'methods_tested': [],
        'error': None
    }
    
    try:
        # Initialize client with retry settings
        client = CRTshClient(
            max_retries=3,
            backoff_factor=1.0,
            timeout=15  # Shorter timeout for testing
        )
        
        # Test getting certificate details via JSON API first
        logger.info("Testing _get_certificate_details (JSON API)...")
        details = client._get_certificate_details(cert_id)
        
        if details:
            logger.info("\n=== Certificate Details ===")
                
            # Basic Info
            logger.info("\n[ Basic Information ]")
            logger.info(f"Version: {details.get('version')}")
            logger.info(f"Serial Number: {details.get('serial_number')}")
                
            # Validity
            validity = details.get('validity', {})
            logger.info("\n[ Validity ]")
            logger.info(f"Not Before: {validity.get('not_before')}")
            logger.info(f"Not After:  {validity.get('not_after')}")
            logger.info(f"Days Remaining: {validity.get('days_remaining')}")
                
            # Subject & Issuer
            logger.info("\n[ Subject ]")
            for key, value in details.get('subject', {}).items():
                logger.info(f"  {key}: {value}")
                    
            logger.info("\n[ Issuer ]")
            for key, value in details.get('issuer', {}).items():
                logger.info(f"  {key}: {value}")
            
            # Public Key
            pubkey = details.get('public_key', {})
            logger.info("\n[ Public Key ]")
            logger.info(f"Type: {pubkey.get('type')}")
            logger.info(f"Bits: {pubkey.get('bits')}")
                
            # Signature Algorithm
            sig_alg = details.get('signature_algorithm', {})
            logger.info("\n[ Signature Algorithm ]")
            logger.info(f"Name: {sig_alg.get('name')}")
                
            # Fingerprints
            if 'fingerprints' in details:
                logger.info("\n[ Fingerprints ]")
                for algo, fingerprint in details['fingerprints'].items():
                    logger.info(f"{algo.upper()}: {fingerprint}")
            
            # Extensions
            if 'extensions' in details:
                logger.info("\n[ Extensions ]")
                for ext_name, ext_value in details['extensions'].items():
                    if isinstance(ext_value, list):
                        logger.info(f"{ext_name}:")
                        for item in ext_value:
                            logger.info(f"  - {item}")
                    elif isinstance(ext_value, dict):
                        logger.info(f"{ext_name}:")
                        for k, v in ext_value.items():
                            logger.info(f"  {k}: {v}")
                    else:
                        logger.info(f"{ext_name}: {ext_value}")
            results['success'] = True
            results['methods_tested'].append('json_api')
        else:
            logger.warning("JSON API method returned no data")
            
            # Fall back to direct download
            logger.info("\nFalling back to direct certificate download...")
            download_details = client._get_certificate_download(cert_id)
            if download_details:
                logger.info("Successfully retrieved certificate via direct download")
                results['success'] = True
                results['methods_tested'].append('direct_download')
            else:
                logger.error("Direct download also failed")
                results['error'] = "All methods failed to retrieve certificate"
                
    except CRTshError as e:
        logger.error(f"crt.sh error: {str(e)}")
        results['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        results['error'] = str(e)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test certificate parsing from crt.sh')
    parser.add_argument('cert_id', type=int, nargs='?', default=4799755430,
                       help='Certificate ID to test (default: 4799755430 - example cert)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    logger.info(f"Starting certificate parsing test for ID: {args.cert_id}")
    results = test_cert_parsing(args.cert_id)
    
    if results['success']:
        logger.info(f"Test completed successfully using methods: {', '.join(results['methods_tested'])}")
        sys.exit(0)
    else:
        logger.error(f"Test failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)
