"""
Script to update the OpenSearch index mapping for certificate documents.
"""
import logging
from datetime import datetime
from src.storage.opensearch_client import OpenSearchClient
from src.config import load_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_certificate_mapping():
    """Update the certificate index mapping with consistent field types."""
    config = load_config()
    client = OpenSearchClient(config.get('opensearch', {}))
    
    index_name = f"{client.index_prefix}certificates"
    
    mapping = {
        "properties": {
            "validity": {
                "properties": {
                    "not_before": {"type": "date"},
                    "not_after": {"type": "date"},
                    "is_valid": {"type": "boolean"}
                }
            }
        }
    }
    
    try:
        # Close the index
        client.client.indices.close(index=index_name)
        
        # Update the mapping
        client.client.indices.put_mapping(
            index=index_name,
            body=mapping
        )
        
        # Reopen the index
        client.client.indices.open(index=index_name)
        
        logger.info(f"Successfully updated mapping for index {index_name}")
        
    except Exception as e:
        logger.error(f"Failed to update mapping: {e}")
        # Make sure to reopen the index if there was an error
        try:
            client.client.indices.open(index=index_name)
        except:
            pass
        raise

if __name__ == "__main__":
    update_certificate_mapping()
