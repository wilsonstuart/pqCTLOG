#!/usr/bin/env python3
"""
Main entry point for the pqCTLOG application.
"""
import argparse
import logging
import sys
from typing import Any, Dict, Optional

from src.config import load_config
from src.ctlog.crtsh_client import CRTshClient
from src.storage.opensearch_client import OpenSearchClient

def setup_logging(config: Dict[str, Any]) -> None:
    """Set up logging configuration."""
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO'))  # Default to INFO
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler with a higher log level
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    # Create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add the handlers to the root logger
    root_logger.addHandler(console_handler)
    
    # Set specific log levels for noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.debug("Logging configured with level: %s", logging.getLevelName(log_level))

def process_certificates(config: Dict[str, Any], domain: Optional[str] = None, 
                        exclude_expired: bool = False) -> None:
    """Process certificates from crt.sh.
    
    Args:
        config: Application configuration
        domain: Optional domain to search for in certificates
        exclude_expired: Whether to exclude expired certificates from search results
    """
    logger = logging.getLogger('pqctlog')
    batch_size = 100  # Default batch size
    
    # Initialize clients
    storage = OpenSearchClient(config['opensearch'])
    crt_client = CRTshClient()
    
    try:
        # Search for certificates on crt.sh
        logger.info("Searching for certificates on crt.sh")
        
        # If a domain was provided, search for certificates for that domain
        search_domain = domain or "%"  # Use wildcard if no domain provided
        logger.info(f"Searching for certificates containing domain: {search_domain}")
        if exclude_expired:
            logger.info("Excluding expired certificates from search results")
        
        # Search for certificates using the crtsh_client
        certificates = crt_client.search_certificates(
            dns_name=search_domain,
            match="%",  # Use wildcard match
            exclude_expired=exclude_expired
        )
            
        if not certificates:
            logger.warning("No certificates found matching the search criteria")
            return
            
        logger.info(f"Found {len(certificates)} certificates matching {search_domain}")
        
        # Process certificates in batches
        for i in range(0, len(certificates), batch_size):
            batch = certificates[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(certificates)-1)//batch_size + 1} with {len(batch)} certificates")
            
            # Store certificates in OpenSearch
            stored_count = storage.bulk_index(
                index="certificates",
                documents=batch,
                id_field="id"
            )
            
            logger.info(f"Successfully stored {stored_count} certificates in batch {i//batch_size + 1}")
            
    except Exception as e:
        logger.error(f"Error processing certificates: {str(e)}", exc_info=True)
        raise

def main():
    """Main entry point for the application."""
    logger = logging.getLogger('pqctlog')
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='pqCTLOG - Post-Quantum Certificate Transparency Log Monitor')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--domain', type=str, help='Search for certificates containing this DNS name')
    parser.add_argument('--exclude-expired', action='store_true',
                      help='Exclude expired certificates from search results')
    parser.add_argument('--log-level', type=str, default='INFO',
                      choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      help='Set the logging level')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Set up logging
        setup_logging(config)
        logger.info("Starting pqCTLOG")
        
        # Process certificates
        process_certificates(
            config=config,
            domain=args.domain,
            exclude_expired=args.exclude_expired
        )
        
        logger.info("Certificate processing completed successfully")
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
