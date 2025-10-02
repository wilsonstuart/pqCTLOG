#!/usr/bin/env python3
"""
Run the pqCTLOG application in development mode.
"""
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from src.main import main as run_application
from src.core.config import load_config

# Add the project root to the Python path before any imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
os.environ['PYTHONPATH'] = str(project_root) + os.pathsep + os.environ.get('PYTHONPATH', '')

# Load environment variables from .env file
env_path = project_root / '.env'
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

def main():
    """Run the application in development mode."""
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Run pqCTLOG in development mode')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--domain', type=str, help='Search for certificates containing this DNS name')
    parser.add_argument('--no-download-certificates', action='store_true',
                      help='Skip downloading certificates (use existing data)')
    parser.add_argument('--exclude-expired', action='store_true',
                      help='Exclude expired certificates from search results')
    parser.add_argument('--include-precerts', action='store_true',
                      help='Include pre-certificates in search results (excluded by default)')
    parser.add_argument('--log-level', type=str, default='INFO',
                      choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      help='Set the logging level')
    
    # Parse command line arguments
    args = parser.parse_args()
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, args.log_level))
    
    # Create console handler with a higher log level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, args.log_level))
    
    # Create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add the console handler to the root logger
    root_logger.addHandler(console_handler)
    
    # Set log level for the main logger
    logging.getLogger('pqctlog').setLevel(getattr(logging, args.log_level))
    
    # Disable overly verbose loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('opensearch').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.debug("Debug logging enabled")
    
    try:
        # Load configuration
        _ = load_config(args.config)
        
        logger.info("Starting pqCTLOG in development mode")
        
        # Prepare command line arguments for main()
        import sys
        cmd_args = []
        if args.domain:
            cmd_args.extend(['--domain', args.domain])
        if args.exclude_expired:
            cmd_args.append('--exclude-expired')
        if args.include_precerts:
            cmd_args.append('--include-precerts')
        if args.log_level:
            cmd_args.extend(['--log-level', args.log_level])
            
        # Save and restore the original command line arguments
        original_argv = sys.argv
        try:
            sys.argv = [sys.argv[0]] + cmd_args
            run_application()
        finally:
            sys.argv = original_argv
        
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
