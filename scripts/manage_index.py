#!/usr/bin/env python3
"""
Index management utility for pqCTLOG.
"""
import argparse
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import load_config
from src.core.utils import setup_logging
from src.storage.opensearch_client import OpenSearchClient


def main():
    """Main entry point for index management."""
    parser = argparse.ArgumentParser(description='Manage OpenSearch indices for pqCTLOG')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                       help='Path to configuration file')
    parser.add_argument('--index', type=str, default='certificates',
                       help='Index name (without prefix)')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear all documents from index')
    
    # Delete command  
    delete_parser = subparsers.add_parser('delete', help='Delete the entire index')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show index statistics')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all indices')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        # Load configuration and setup
        config = load_config(args.config)
        setup_logging(config)
        
        client = OpenSearchClient(config)
        
        if args.command == 'clear':
            print(f"Clearing index '{args.index}'...")
            if client.clear_index(args.index):
                print("✓ Index cleared successfully")
            else:
                print("✗ Failed to clear index")
                sys.exit(1)
                
        elif args.command == 'delete':
            print(f"Deleting index '{args.index}'...")
            confirm = input(f"Are you sure you want to delete index '{args.index}'? (y/N): ")
            if confirm.lower() == 'y':
                if client.delete_index(args.index):
                    print("✓ Index deleted successfully")
                else:
                    print("✗ Failed to delete index")
                    sys.exit(1)
            else:
                print("Operation cancelled")
                
        elif args.command == 'stats':
            print(f"Getting statistics for index '{args.index}'...")
            stats = client.get_index_stats(args.index)
            
            if stats.get('exists'):
                print(f"✓ Index exists")
                print(f"  Documents: {stats['document_count']:,}")
                print(f"  Size: {stats['size_human']} ({stats['size_in_bytes']:,} bytes)")
            else:
                print("✗ Index does not exist")
                if 'error' in stats:
                    print(f"  Error: {stats['error']}")
                    
        elif args.command == 'list':
            print("Listing all indices...")
            try:
                indices = client.client.indices.get_alias()
                pqctlog_indices = [name for name in indices.keys() 
                                 if name.startswith(client.index_prefix)]
                
                if pqctlog_indices:
                    print("pqCTLOG indices:")
                    for index_name in sorted(pqctlog_indices):
                        base_name = index_name[len(client.index_prefix):]
                        stats = client.get_index_stats(base_name)
                        if stats.get('exists'):
                            print(f"  {base_name}: {stats['document_count']:,} documents, {stats['size_human']}")
                        else:
                            print(f"  {base_name}: (error getting stats)")
                else:
                    print("No pqCTLOG indices found")
                    
            except Exception as e:
                print(f"✗ Error listing indices: {e}")
                sys.exit(1)
        
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()