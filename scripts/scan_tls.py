#!/usr/bin/env python3
"""
Standalone TLS scanner for analyzing cipher suites and TLS configurations.
"""
import argparse
import json
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import load_config
from src.core.utils import setup_logging
from src.scanner.tls_scanner import TLSScanner
from src.storage.opensearch_client import OpenSearchClient


def main():
    """Main entry point for TLS scanning."""
    parser = argparse.ArgumentParser(description='TLS Scanner for pqCTLOG')
    parser.add_argument('domains', nargs='+', help='Domain names to scan')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                       help='Path to configuration file')
    parser.add_argument('--output', type=str, choices=['json', 'summary', 'detailed'],
                       default='summary', help='Output format')
    parser.add_argument('--store', action='store_true',
                       help='Store results in OpenSearch')
    parser.add_argument('--ports', type=int, nargs='+',
                       help='Ports to scan (overrides config)')
    parser.add_argument('--timeout', type=int,
                       help='Connection timeout in seconds (overrides config)')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        setup_logging(config)
        
        # Override config with command line args if provided
        if args.ports:
            config.tls_scanner.ports = args.ports
        if args.timeout:
            config.tls_scanner.timeout = args.timeout
        
        # Initialize scanner
        scanner = TLSScanner(config)
        
        print(f"Scanning {len(args.domains)} domains...")
        results = scanner.scan_domains(args.domains)
        
        # Output results
        if args.output == 'json':
            print(json.dumps(results, indent=2, default=str))
        elif args.output == 'summary':
            print_summary(results)
        elif args.output == 'detailed':
            print_detailed(results)
        
        # Store in OpenSearch if requested
        if args.store:
            storage = OpenSearchClient(config)
            stored = storage.bulk_index("scan_results", results, "domain")
            print(f"\nStored {stored} results in OpenSearch")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def print_summary(results):
    """Print a summary of scan results."""
    print(f"\n{'='*60}")
    print("TLS SCAN SUMMARY")
    print(f"{'='*60}")
    
    for result in results:
        domain = result['domain']
        summary = result.get('summary', {})
        
        print(f"\n🌐 {domain}")
        print(f"   Ports scanned: {summary.get('total_ports_scanned', 0)}")
        print(f"   Successful connections: {summary.get('successful_connections', 0)}")
        
        tls_versions = summary.get('tls_versions_supported', [])
        if tls_versions:
            print(f"   TLS versions: {', '.join(tls_versions)}")
        
        cipher_count = len(summary.get('cipher_suites_found', []))
        if cipher_count > 0:
            print(f"   Cipher suites: {cipher_count} found")
        
        if summary.get('post_quantum_ready'):
            print("   🔒 Post-quantum ready: YES")
        else:
            print("   🔒 Post-quantum ready: NO")
        
        issues = summary.get('security_issues', [])
        if issues:
            print(f"   ⚠️  Security issues: {len(issues)}")
            for issue in issues[:3]:  # Show first 3 issues
                print(f"      - {issue}")
            if len(issues) > 3:
                print(f"      ... and {len(issues) - 3} more")


def print_detailed(results):
    """Print detailed scan results."""
    for result in results:
        domain = result['domain']
        print(f"\n{'='*80}")
        print(f"DETAILED SCAN RESULTS FOR: {domain}")
        print(f"{'='*80}")
        print(f"Scan time: {result.get('scan_timestamp', 'Unknown')}")
        
        ports = result.get('ports', {})
        for port_str, port_data in ports.items():
            print(f"\n--- Port {port_str} ---")
            
            if port_data.get('success'):
                print("✅ Connection successful")
                print(f"Connection time: {port_data.get('connection_time', 0):.3f}s")
                
                # TLS versions
                tls_versions = port_data.get('tls_versions', {})
                print("\nTLS Versions:")
                for version, supported in tls_versions.items():
                    status = "✅" if supported else "❌"
                    print(f"  {status} {version}")
                
                # Cipher suites
                cipher_suites = port_data.get('cipher_suites', [])
                if cipher_suites:
                    print("\nCipher Suites:")
                    for cipher in cipher_suites:
                        security = cipher.get('security_level', 'unknown')
                        pq_status = "🔒" if cipher.get('is_post_quantum') else "🔓"
                        preferred = "⭐" if cipher.get('is_preferred') else "  "
                        print(f"  {preferred} {pq_status} {cipher['name']} ({security}, {cipher.get('bits', 0)} bits)")
                
                # Certificate info
                cert_info = port_data.get('certificate_info')
                if cert_info:
                    print(f"\nCertificate:")
                    subject = cert_info.get('subject', {})
                    if subject.get('commonName'):
                        print(f"  Subject: {subject['commonName']}")
                    if cert_info.get('not_after'):
                        print(f"  Expires: {cert_info['not_after']}")
                
                # Security issues
                issues = port_data.get('security_issues', [])
                if issues:
                    print(f"\n⚠️  Security Issues:")
                    for issue in issues:
                        print(f"  - {issue}")
            else:
                print("❌ Connection failed")
                if port_data.get('error'):
                    print(f"Error: {port_data['error']}")


if __name__ == "__main__":
    main()