#!/usr/bin/env python3
"""
Script to set up OpenSearch index with proper mappings for certificate data.
"""
import json
import logging
import sys
from pathlib import Path
from opensearchpy import OpenSearch
from config import load_config

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_certificate_mapping():
    """Return the mapping for the certificates index."""
    return {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "analysis": {
                "analyzer": {
                    "lowercase_keyword": {
                        "type": "custom",
                        "tokenizer": "keyword",
                        "filter": ["lowercase"]
                    }
                }
            }
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keywords": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "keyword"
                        }
                    }
                }
            ],
            "properties": {
                # Core identification
                "id": {"type": "keyword"},
                "serial_number": {"type": "keyword"},
                "search_domain": {"type": "keyword"},
                "source": {"type": "keyword"},
                
                # Certificate details
                "common_name": {"type": "keyword"},
                "name_value": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "entry_timestamp": {"type": "date"},
                "not_before": {"type": "date"},
                "not_after": {"type": "date"},
                "issuer_name": {"type": "keyword"},
                "issuer_ca_id": {"type": "long"},
                "result_count": {"type": "integer"},
                "signature_algorithm": {"type": "keyword"},
                "public_key_algorithm": {"type": "keyword"},
                "public_key_size": {"type": "integer"},
                
                # Processed fields
                "subject_common_name": {"type": "keyword"},
                "subject_alternative_names": {"type": "keyword"},
                
                # Nested objects
                "validity": {
                    "type": "object",
                    "properties": {
                        "not_before": {"type": "date"},
                        "not_after": {"type": "date"}
                    }
                },
                "issuer": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "keyword"},
                        "ca_id": {"type": "long"},
                        "common_name": {"type": "keyword"},
                        "organization": {"type": "keyword"},
                        "organizational_unit": {"type": "keyword"},
                        "country": {"type": "keyword"},
                        "locality": {"type": "keyword"},
                        "state": {"type": "keyword"},
                        "email": {"type": "keyword"}
                    }
                },
                "subject": {
                    "type": "object",
                    "properties": {
                        "common_name": {"type": "keyword"},
                        "organization": {"type": "keyword"},
                        "organizational_unit": {"type": "keyword"},
                        "country": {"type": "keyword"},
                        "locality": {"type": "keyword"},
                        "state": {"type": "keyword"},
                        "email": {"type": "keyword"}
                    }
                },
                
                # Certificate details
                "certificate_details": {
                    "type": "object",
                    "properties": {
                        "signature_algorithm": {"type": "keyword"},
                        "public_key_algorithm": {"type": "keyword"},
                        "public_key_size": {"type": "integer"},
                        "serial_number_hex": {"type": "keyword"},
                        "version": {"type": "keyword"}
                    }
                },
                
                # Raw data and metadata
                "raw_data": {"enabled": False},  # Store as is without indexing
                "certificate_metadata": {
                    "type": "object",
                    "properties": {
                        "basic_info_only": {"type": "boolean"},
                        "downloaded": {"type": "boolean"},
                        "source": {"type": "keyword"},
                        "last_updated": {"type": "date"},
                        "version": {"type": "integer"}
                    }
                },
                "parsed_certificate": {
                    "properties": {
                        "issuer": {
                            "properties": {
                                "commonName": {"type": "keyword"},
                                "organizationName": {"type": "keyword"},
                                "organizationalUnitName": {"type": "keyword"},
                                "countryName": {"type": "keyword"}
                            }
                        },
                        "subject": {
                            "properties": {
                                "commonName": {"type": "keyword"},
                                "organizationName": {"type": "keyword"},
                                "organizationalUnitName": {"type": "keyword"},
                                "countryName": {"type": "keyword"}
                            }
                        },
                        "validity": {
                            "properties": {
                                "not_before": {"type": "date"},
                                "not_after": {"type": "date"}
                            }
                        },
                        "extensions": {
                            "properties": {
                                "subjectAltName": {"type": "keyword"},
                                "keyUsage": {"type": "keyword"},
                                "extendedKeyUsage": {"type": "keyword"}
                            }
                        },
                        "signature_algorithm": {"type": "keyword"},
                        "public_key_algorithm": {"type": "keyword"},
                        "public_key_size": {"type": "integer"},
                        "version": {"type": "integer"},
                        "fingerprint_sha256": {"type": "keyword"}
                    }
                }
            }
        }
    }

def setup_opensearch():
    """Set up OpenSearch with the correct index and mappings."""
    try:
        # Load configuration
        config = load_config()
        opensearch_config = config.get('opensearch', {})
        index_prefix = opensearch_config.get('index_prefix', 'pqctlog_')
        index_name = f"{index_prefix}certificates"
        
        # Create OpenSearch client
        client = OpenSearch(
            hosts=[{'host': opensearch_config.get('host', 'localhost'), 
                   'port': opensearch_config.get('port', 9200)}],
            http_auth=(
                opensearch_config.get('http_auth', {}).get('username', 'admin'),
                opensearch_config.get('http_auth', {}).get('password', 'admin')
            ) if opensearch_config.get('http_auth') else None,
            use_ssl=opensearch_config.get('use_ssl', False),
            verify_certs=opensearch_config.get('verify_certs', False),
            ssl_show_warn=opensearch_config.get('ssl_show_warn', False)
        )
        
        # Delete existing index if it exists
        if client.indices.exists(index=index_name):
            logger.info(f"Deleting existing index: {index_name}")
            client.indices.delete(index=index_name)
        
        # Create new index with mapping
        mapping = create_certificate_mapping()
        logger.info(f"Creating index: {index_name}")
        logger.debug(f"Index mapping: {json.dumps(mapping, indent=2)}")
        
        response = client.indices.create(
            index=index_name,
            body=mapping
        )
        
        if response.get('acknowledged'):
            logger.info(f"Successfully created index: {index_name}")
            return True
        else:
            logger.error(f"Failed to create index: {response}")
            return False
            
    except Exception as e:
        logger.error(f"Error setting up OpenSearch: {str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    setup_opensearch()
