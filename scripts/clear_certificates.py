#!/usr/bin/env python3
"""
Quick script to clear the certificates index.
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import load_config
from src.storage.opensearch_client import OpenSearchClient

def main():
    """Clear the certificates index."""
    try:
        config = load_config()
        client = OpenSearchClient(config)
        
        print("Clearing certificates index...")
        if client.clear_index("certificates"):
            print("✓ Certificates index cleared successfully")
        else:
            print("✗ Failed to clear certificates index")
            sys.exit(1)
            
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()