#!/usr/bin/env python3
"""
Test script for certificate search functionality.
"""
import sys
import logging
import argparse
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ctlog.crtsh_client import CRTshClient
from storage.opensearch_client import OpenSearchClient

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_search_certificates(domain: str = "example.com"):
    """Test certificate search and storage."""
    try:
        # Initialize clients
        logger.info("Initializing CRTshClient...")
        client = CRTshClient(
            max_retries=5,
            backoff_factor=1.0,
            timeout=30,
            rate_limit_delay=2.0
        )
        
        # Search for certificates
        logger.info(f"Searching for certificates containing: {domain}")
        try:
            # Search for all certificates related to the domain
            logger.debug("Calling search_certificates...")
            certificates = client.search_certificates(domain, exclude_expired=True)
            
            if not certificates:
                logger.warning("No certificates found")
                return
                
            logger.info(f"Found {len(certificates)} certificates")
            
            # Log some sample certificates
            for i, cert in enumerate(certificates[:5], 1):
                logger.info(f"Certificate {i}:")
                logger.info(f"  ID: {cert.get('id')}")
                logger.info(f"  Names: {', '.join(cert.get('names', []))}")
                logger.info(f"  Issuer: {cert.get('issuer', 'N/A')}")
                logger.info(f"  Valid from {cert.get('validity', {}).get('not_before')} to {cert.get('validity', {}).get('not_after')}")
                
            if len(certificates) > 5:
                logger.info(f"... and {len(certificates) - 5} more certificates")
                
        except Exception as e:
            logger.error(f"Error during certificate search: {str(e)}", exc_info=True)
            return
        
        # Initialize OpenSearch client
        opensearch_config = {
            'http_auth': {
                'username': 'admin',
                'password': 'admin'
            },
            'hosts': [{'host': 'localhost', 'port': 9200}],
            'use_ssl': False,
            'verify_certs': False,
            'ssl_show_warn': False
        }
        
        storage = OpenSearchClient(opensearch_config)
        
        # Store certificates in batches
        batch_size = 50
        for i in range(0, len(certificates), batch_size):
            batch = certificates[i:i + batch_size]
            processed_batch = []
            
            for cert in batch:
                try:
                    # Get full certificate details
                    cert_details = client._get_certificate_details(cert['id'])
                    if cert_details:
                        cert_details['search_domain'] = domain
                        processed_batch.append(cert_details)
                except Exception as e:
                    logger.error(f"Error processing certificate {cert.get('id', 'unknown')}: {str(e)}")
            
            # Store batch in OpenSearch
            if processed_batch:
                success_count = storage.bulk_index_certificates(processed_batch)
                logger.info(f"Indexed batch {i//batch_size + 1}: {success_count}/{len(processed_batch)} certificates")
            
            # Be nice to the API
            import time
            time.sleep(1)
        
        logger.info("Test completed successfully")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test certificate search functionality")
    parser.add_argument("--domain", type=str, default="example.com",
                       help="Domain to search for in certificates")
    
    args = parser.parse_args()
    test_search_certificates(args.domain)
