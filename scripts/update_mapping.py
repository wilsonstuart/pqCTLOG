"""
Script to update the OpenSearch index mapping for certificate documents.
"""
import logging
import time
from datetime import datetime
from src.storage.opensearch_client import OpenSearchClient
from src.config import load_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_certificate_mapping():
    """Update the certificate index mapping with consistent field types and proper nested fields."""
    config = load_config()
    client = OpenSearchClient(config.get('opensearch', {}))
    
    index_name = f"{client.index_prefix}certificates"
    temp_index = f"{index_name}_temp"
    
    # Define the complete mapping with proper nested types
    mapping = {
        "mappings": {
            "properties": {
                "validity": {
                    "properties": {
                        "not_before": {"type": "date"},
                        "not_after": {"type": "date"},
                        "is_valid": {"type": "boolean"}
                    }
                },
                "is_precertificate": {
                    "type": "boolean"
                },
                "ct_log_entries": {
                    "type": "nested",
                    "properties": {
                        "entry_type": {"type": "keyword"},
                        "log_id": {"type": "keyword"},
                        "timestamp": {"type": "date"}
                    }
                },
                # Include all other fields from the original mapping
                "basic_constraints": {"type": "object", "enabled": True},
                "compliance": {"type": "object", "enabled": True},
                "created_at": {"type": "date"},
                "extended_key_usage": {"type": "keyword"},
                "extensions": {"type": "object"},
                "id": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "is_ca": {"type": "boolean"},
                "is_self_signed": {"type": "boolean"},
                "issuer": {"type": "object", "enabled": True},
                "issuer_dn": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "key_algorithm": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "key_size": {"type": "long"},
                "key_type": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "key_usage": {"type": "keyword"},
                "processed_at": {"type": "date"},
                "public_key": {"type": "object", "enabled": True},
                "raw": {"type": "object", "enabled": True},
                "san": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "serial_number": {"type": "keyword"},
                "sha256_fingerprint": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "signature_algorithm": {"type": "object", "enabled": True},
                "subject": {"type": "object", "enabled": True},
                "subject_alternative_names": {"type": "keyword"},
                "subject_dn": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "tls_scan": {"type": "object", "enabled": True},
                "updated_at": {"type": "date"},
                "version": {"type": "long"}
            }
        }
    }
    
    try:
        # Create a new index with the updated mapping
        logger.info(f"Creating new index with updated mapping: {temp_index}")
        client.client.indices.create(index=temp_index, body=mapping)
        
        # Reindex all documents from the old index to the new one
        logger.info("Starting reindexing process...")
        reindex_body = {
            "source": {"index": index_name},
            "dest": {"index": temp_index}
        }
        
        reindex_response = client.client.reindex(
            body=reindex_body,
            wait_for_completion=False
        )
        
        task_id = reindex_response['task']
        logger.info(f"Reindexing started with task ID: {task_id}")
        
        # Wait for the reindexing to complete
        while True:
            task_status = client.client.tasks.get(task_id=task_id)
            if task_status['completed']:
                if task_status.get('error'):
                    logger.error(f"Reindexing failed: {task_status['error']}")
                    raise Exception(f"Reindexing failed: {task_status['error']}")
                else:
                    logger.info("Reindexing completed successfully")
                    break
            time.sleep(5)  # Wait 5 seconds before checking again
        
        # Delete the old index
        logger.info(f"Deleting old index: {index_name}")
        client.client.indices.delete(index=index_name)
        
        # Create an alias from the old index name to the new index
        logger.info(f"Creating alias from {temp_index} to {index_name}")
        client.client.indices.put_alias(index=temp_index, name=index_name)
        
        logger.info(f"Successfully updated index mapping for {index_name}")
        
    except Exception as e:
        logger.error(f"Failed to update index mapping: {e}")
        # Clean up the temporary index if it was created
        try:
            if client.client.indices.exists(index=temp_index):
                client.client.indices.delete(index=temp_index)
        except Exception as cleanup_error:
            logger.error(f"Error during cleanup: {cleanup_error}")
        raise

def update_existing_documents():
    """Update existing documents to set is_precertificate based on ct_log_entries.entry_type."""
    config = load_config()
    client = OpenSearchClient(config.get('opensearch', {}))
    index_name = f"{client.index_prefix}certificates"
    
    # First, find all documents that have ct_log_entries.entry_type == 'precert'
    query = {
        "query": {
            "nested": {
                "path": "ct_log_entries",
                "query": {
                    "term": {"ct_log_entries.entry_type": "precert"}
                }
            }
        },
        "size": 10000  # Adjust based on your dataset size
    }
    
    try:
        # Use the scroll API to get all matching documents
        response = client.client.search(
            index=index_name,
            scroll='2m',
            body=query
        )
        
        scroll_id = response['_scroll_id']
        hits = response['hits']['hits']
        
        updated_count = 0
        
        # Process all matching documents
        while hits:
            for doc in hits:
                doc_id = doc['_id']
                # Update the document to set is_precertificate to true
                client.client.update(
                    index=index_name,
                    id=doc_id,
                    body={
                        "doc": {
                            "is_precertificate": True
                        }
                    }
                )
                updated_count += 1
                
                if updated_count % 100 == 0:
                    logger.info(f"Updated {updated_count} documents so far...")
            
            # Get the next batch of results
            response = client.client.scroll(
                scroll_id=scroll_id,
                scroll='2m'
            )
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
        
        logger.info(f"Successfully updated {updated_count} documents with is_precertificate=True")
        
    except Exception as e:
        logger.error(f"Failed to update documents: {e}")
    finally:
        # Clear the scroll
        if 'scroll_id' in locals():
            client.client.clear_scroll(scroll_id=scroll_id)

if __name__ == "__main__":
    update_certificate_mapping()
    update_existing_documents()
