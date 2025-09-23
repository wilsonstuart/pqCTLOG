#!/usr/bin/env python3
"""
Initialize OpenSearch indices and settings.
"""
import logging
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.opensearch_client import OpenSearchClient
from src.config import load_config

def main():
    """Initialize OpenSearch indices and settings."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = load_config()
        
        # Initialize OpenSearch client
        client = OpenSearchClient(config.get('opensearch', {}))
        
        logger.info("Successfully connected to OpenSearch")
        logger.info("Indices have been created with the following mappings:")
        
        # List all indices
        indices = client.client.indices.get_alias(index="*")
        for index_name in indices:
            logger.info(f"- {index_name}")
        
        logger.info("OpenSearch initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize OpenSearch: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
