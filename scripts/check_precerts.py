#!/usr/bin/env python3
"""
Script to check pre-certificate data in OpenSearch.
"""
import logging
from opensearchpy import OpenSearch

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('check_precerts')

def main():
    logger = setup_logging()
    
    # OpenSearch configuration
    host = 'localhost'
    port = 9200
    http_auth = ('admin', 'admin')
    use_ssl = False
    verify_certs = False
    
    # Create OpenSearch client
    client = OpenSearch(
        [{'host': host, 'port': port}],
        http_auth=http_auth,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        ssl_show_warn=False
    )
    
    index_name = 'pqctlog_certificates'
    
    # Check if index exists
    if not client.indices.exists(index=index_name):
        logger.error(f"Index {index_name} does not exist")
        return
    
    # Get the mapping and check the ct_log_entries field structure
    mapping = client.indices.get_mapping(index=index_name)
    logger.info(f"Mapping for {index_name}:")
    
    # Print the full mapping for reference
    print(mapping)
    
    # Check if ct_log_entries field exists in the mapping
    if 'mappings' in mapping and 'properties' in mapping['mappings']:
        if 'ct_log_entries' in mapping['mappings']['properties']:
            logger.info("ct_log_entries field exists in the mapping")
            logger.info(f"ct_log_entries mapping: {mapping['mappings']['properties']['ct_log_entries']}")
        else:
            logger.warning("ct_log_entries field does not exist in the mapping")
    else:
        logger.warning("Could not find properties in the mapping")
    
    # Check for documents with non-empty ct_log_entries
    query = {
        "query": {
            "exists": {
                "field": "ct_log_entries"
            }
        },
        "size": 5,
        "_source": ["id", "serial_number", "is_precertificate", "ct_log_entries"]
    }
    
    logger.info("Searching for documents with ct_log_entries...")
    results = client.search(index=index_name, body=query)
    
    if results['hits']['total']['value'] > 0:
        logger.info(f"Found {results['hits']['total']['value']} documents with ct_log_entries")
        for hit in results['hits']['hits']:
            print(f"ID: {hit['_id']}")
            print(f"Serial Number: {hit['_source'].get('serial_number')}")
            print(f"is_precertificate: {hit['_source'].get('is_precertificate', 'field not present')}")
            print(f"ct_log_entries: {hit['_source'].get('ct_log_entries')}")
            print("-" * 50)
    else:
        logger.info("No documents with ct_log_entries found")
    
    # Also check a few random documents
    query = {
        "query": {
            "function_score": {
                "random_score": {}
            }
        },
        "size": 5,
        "_source": ["id", "serial_number", "is_precertificate", "ct_log_entries"]
    }
    
    logger.info("Searching for pre-certificates...")
    results = client.search(index=index_name, body=query)
    
    if results['hits']['total']['value'] > 0:
        logger.info(f"Examining {results['hits']['total']['value']} random certificates")
        for hit in results['hits']['hits']:
            print(f"ID: {hit['_id']}")
            print(f"Serial Number: {hit['_source'].get('serial_number')}")
            print(f"is_precertificate: {hit['_source'].get('is_precertificate', 'field not present')}")
            if 'ct_log_entries' in hit['_source']:
                print(f"ct_log_entries: {hit['_source']['ct_log_entries']}")
            print("-" * 50)
    else:
        logger.info("No pre-certificates found in the index")
    
    # Check some random certificates
    logger.info("Checking some random certificates...")
    random_query = {
        "query": {
            "function_score": {
                "random_score": {}
            }
        },
        "size": 5,
        "_source": ["id", "serial_number", "subject.common_name", "is_precertificate", "issuer.common_name"]
    }
    
    results = client.search(index=index_name, body=random_query)
    for hit in results['hits']['hits']:
        print(f"ID: {hit['_id']}")
        print(f"Source: {hit['_source']}")
        print("-" * 50)

if __name__ == "__main__":
    main()
