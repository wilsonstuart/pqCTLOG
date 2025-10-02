#!/usr/bin/env python3
"""
Debug script to see what crt.sh actually returns.
"""
import json
import requests
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def test_crtsh_response(domain="example.com", limit=3):
    """Test what crt.sh actually returns."""
    print(f"Testing crt.sh response for domain: {domain}")
    
    try:
        response = requests.get(
            "https://crt.sh/",
            params={
                'q': f'%.{domain}',
                'output': 'json'
            },
            timeout=30
        )
        response.raise_for_status()
        
        certificates = response.json()
        if not isinstance(certificates, list):
            print(f"Unexpected response type: {type(certificates)}")
            return
        
        print(f"Found {len(certificates)} certificates")
        
        # Show the first few certificates with all their fields
        for i, cert in enumerate(certificates[:limit]):
            print(f"\n--- Certificate {i+1} ---")
            print(json.dumps(cert, indent=2, default=str))
            
            # Specifically check the fields we're interested in
            print(f"\nKey fields for certificate {i+1}:")
            print(f"  id: {cert.get('id')}")
            print(f"  common_name: {cert.get('common_name')}")
            print(f"  name_value: {cert.get('name_value')}")
            print(f"  issuer_name: {cert.get('issuer_name')}")
            print(f"  serial_number: {cert.get('serial_number')}")
            print(f"  entry_type: {cert.get('entry_type')}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    test_crtsh_response(domain)