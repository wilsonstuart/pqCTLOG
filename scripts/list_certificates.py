#!/usr/bin/env python3
"""
Script to list certificates stored in OpenSearch.
"""
import argparse
import logging

from src.storage.opensearch_client import OpenSearchClient
from src.config import load_config

def setup_logging(log_level: str = "INFO") -> None:
    """Set up basic logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def list_certificates(limit: int = 10, pretty: bool = True) -> None:
    """List certificates from OpenSearch.
    
    Args:
        limit: Maximum number of certificates to display
        pretty: Whether to pretty-print the output
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize OpenSearch client
        config = load_config()
        client = OpenSearchClient(config)
        
        # Query OpenSearch
        index_name = f"{client.index_prefix}certificates"
        query = {
            "size": limit,
            "sort": [{"entry_timestamp": {"order": "desc"}}],
            "query": {"match_all": {}}
        }
        
        response = client.client.search(index=index_name, body=query)
        
        # Process and display results
        hits = response.get('hits', {}).get('hits', [])
        logger.info(f"Found {len(hits)} certificates in OpenSearch")
        
        for i, hit in enumerate(hits, 1):
            source = hit.get('_source', {})
            print(f"\n=== Certificate {i} ===")
            print(f"ID: {hit.get('_id')}")
            print(f"Common Name: {source.get('common_name')}")
            print(f"Issuer: {source.get('issuer_name', {}).get('common_name', 'N/A')}")
            print(f"Valid From: {source.get('not_before')}")
            print(f"Valid To: {source.get('not_after')}")
            
            # Print all name values (SANs)
            name_values = source.get('name_value', [])
            if name_values:
                print("Subject Alternative Names:")
                for name in name_values:
                    print(f"  - {name}")
            
            # Print the first few fields of the certificate
            if pretty:
                print("\nCertificate Details:")
                for key, value in list(source.items())[:10]:  # Show first 10 fields
                    if key not in ['name_value', 'issuer_name', 'common_name', 'not_before', 'not_after']:
                        print(f"{key}: {value}")
                
                if len(source) > 10:
                    print("... (more fields available)")
            
            print("-" * 50)
            
    except Exception as e:
        logger.error(f"Error listing certificates: {str(e)}", exc_info=True)
        raise

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='List certificates from OpenSearch')
    parser.add_argument('--limit', type=int, default=10, help='Maximum number of certificates to list')
    parser.add_argument('--log-level', default='INFO', 
                      choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                      help='Set the logging level')
    
    args = parser.parse_args()
    setup_logging(args.log_level)
    
    try:
        list_certificates(limit=args.limit)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
