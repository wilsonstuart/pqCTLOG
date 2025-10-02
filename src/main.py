#!/usr/bin/env python3
"""
Main entry point for the pqCTLOG application.
"""
import argparse
import logging
import sys
from typing import Optional

from src.core.config import load_config
from src.core.utils import setup_logging, validate_domain
from src.ctlog.simplified_crtsh_client import SimplifiedCRTshClient
from src.storage.opensearch_client import OpenSearchClient



class CertificateProcessor:
    """Handles certificate processing operations."""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('pqctlog.processor')
        self.storage = OpenSearchClient(config)
        self.crt_client = SimplifiedCRTshClient()
    
    def process_certificates(self, domain: Optional[str] = None, 
                           exclude_expired: bool = False, 
                           exclude_precerts: bool = True,
                           download_full_certs: bool = False) -> None:
        """Process certificates from crt.sh."""
        if not domain:
            self.logger.error("Domain is required for certificate search")
            return
        
        if not validate_domain(domain):
            self.logger.error(f"Invalid domain format: {domain}")
            return
        
        try:
            self.logger.info(f"Searching for certificates for domain: {domain}")
            
            certificates = self.crt_client.search_certificates(
                dns_name=domain,
                exclude_expired=exclude_expired,
                exclude_precerts=exclude_precerts,
                download_full_certs=download_full_certs
            )
            
            if not certificates:
                self.logger.warning("No certificates found matching the search criteria")
                return
            
            self.logger.info(f"Found {len(certificates)} certificates")
            
            # Store certificates in batches
            stored_count = self.storage.bulk_index(
                index="certificates",
                documents=certificates,
                id_field="id"
            )
            
            self.logger.info(f"Successfully stored {stored_count} certificates")
            
        except Exception as e:
            self.logger.error(f"Error processing certificates: {e}", exc_info=True)
            raise

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description='pqCTLOG - Post-Quantum Certificate Transparency Log Monitor'
    )
    parser.add_argument(
        '--config', 
        type=str, 
        default='config/config.yaml',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--domain', 
        type=str, 
        required=True,
        help='Domain name to search for certificates'
    )
    parser.add_argument(
        '--exclude-expired', 
        action='store_true',
        help='Exclude expired certificates from search results'
    )
    parser.add_argument(
        '--include-precerts', 
        action='store_true',
        help='Include pre-certificates in search results (excluded by default)'
    )
    parser.add_argument(
        '--download-full-certs',
        action='store_true',
        help='Download and parse full certificate details (slower but more complete)'
    )
    parser.add_argument(
        '--log-level', 
        type=str, 
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set the logging level'
    )
    return parser


def main():
    """Main entry point for the application."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Override log level from command line
        if args.log_level:
            config.logging.level = args.log_level
        
        # Set up logging
        setup_logging(config)
        logger = logging.getLogger('pqctlog')
        logger.info("Starting pqCTLOG")
        
        # Process certificates
        processor = CertificateProcessor(config)
        processor.process_certificates(
            domain=args.domain,
            exclude_expired=args.exclude_expired,
            exclude_precerts=not args.include_precerts,
            download_full_certs=args.download_full_certs
        )
        
        logger.info("Certificate processing completed successfully")
        
    except KeyboardInterrupt:
        logging.getLogger('pqctlog').info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.getLogger('pqctlog').error(f"Application error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
