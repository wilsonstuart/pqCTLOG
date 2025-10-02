#!/usr/bin/env python3
"""
Comprehensive post-quantum TLS testing using multiple methods.
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
from src.scanner.pq_client import PQTLSClient


def main():
    """Main entry point for comprehensive PQ testing."""
    parser = argparse.ArgumentParser(description='Comprehensive Post-Quantum TLS Testing')
    parser.add_argument('domains', nargs='*', help='Domain names to test')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                       help='Path to configuration file')
    parser.add_argument('--port', type=int, default=443,
                       help='Port to test (default: 443)')
    parser.add_argument('--output', type=str, choices=['summary', 'detailed', 'json'],
                       default='detailed', help='Output format')
    parser.add_argument('--install-guide', action='store_true',
                       help='Show installation guide for PQ tools')
    
    args = parser.parse_args()
    
    if args.install_guide:
        show_installation_guide()
        return
    
    if not args.domains:
        parser.error("Domain names are required unless using --install-guide")
    
    try:
        # Load configuration
        config = load_config(args.config)
        setup_logging(config)
        
        # Initialize clients
        tls_scanner = TLSScanner(config)
        pq_client = PQTLSClient(config)
        
        # Show available tools
        tools_info = pq_client.get_available_tools_info()
        print("Post-Quantum Testing Tools Status")
        print("=" * 50)
        for tool, available in tools_info['available_tools'].items():
            status = "✅ Available" if available else "❌ Not Available"
            print(f"{tool}: {status}")
        
        if not any(tools_info['available_tools'].values()):
            print("\n⚠️  No PQ-capable tools detected!")
            print("Run with --install-guide for installation instructions")
            print("Falling back to standard TLS scanning with PQ indicators...\n")
        
        # Test each domain
        results = []
        for domain in args.domains:
            print(f"\n{'='*60}")
            print(f"Testing: {domain}")
            print(f"{'='*60}")
            
            # Standard TLS scan with PQ assessment
            tls_result = tls_scanner.scan_domain(domain)
            
            # Direct PQ testing if tools available
            pq_result = None
            if any(tools_info['available_tools'].values()):
                pq_result = pq_client.test_pq_support(domain, args.port)
            
            result = {
                'domain': domain,
                'tls_scan': tls_result,
                'pq_test': pq_result,
                'tools_available': tools_info['available_tools']
            }
            results.append(result)
            
            # Display results
            if args.output == 'json':
                continue  # Print all JSON at the end
            elif args.output == 'summary':
                print_summary_result(result)
            else:  # detailed
                print_detailed_result(result)
        
        # Output JSON if requested
        if args.output == 'json':
            print(json.dumps(results, indent=2, default=str))
        
        # Show recommendations
        if tools_info.get('recommendations'):
            print(f"\n{'='*60}")
            print("Recommendations")
            print(f"{'='*60}")
            for rec in tools_info['recommendations']:
                print(f"• {rec}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def print_summary_result(result):
    """Print summary of test results."""
    domain = result['domain']
    tls_scan = result.get('tls_scan', {})
    pq_test = result.get('pq_test', {})
    
    print(f"\n🌐 {domain}")
    
    # TLS scan results
    if tls_scan and tls_scan.get('summary', {}).get('successful_connections', 0) > 0:
        summary = tls_scan['summary']
        tls_versions = summary.get('tls_versions_supported', [])
        print(f"   TLS Versions: {', '.join(tls_versions) if tls_versions else 'None'}")
        
        pq_assessment = tls_scan.get('summary', {}).get('post_quantum_ready', False)
        print(f"   Standard PQ Assessment: {'✅ Ready' if pq_assessment else '❌ Not Ready'}")
    
    # PQ test results
    if pq_test:
        pq_support = pq_test.get('pq_support', False)
        algorithms = pq_test.get('pq_algorithms', [])
        print(f"   🔒 Actual PQ Support: {'✅ YES' if pq_support else '❌ NO'}")
        if algorithms:
            print(f"   🔑 PQ Algorithms: {', '.join(algorithms)}")


def print_detailed_result(result):
    """Print detailed test results."""
    domain = result['domain']
    tls_scan = result.get('tls_scan', {})
    pq_test = result.get('pq_test', {})
    tools_available = result.get('tools_available', {})
    
    print(f"\n🌐 Domain: {domain}")
    
    # Standard TLS scan results
    if tls_scan:
        print(f"\n📡 Standard TLS Scan:")
        summary = tls_scan.get('summary', {})
        
        if summary.get('successful_connections', 0) > 0:
            tls_versions = summary.get('tls_versions_supported', [])
            print(f"   TLS Versions: {', '.join(tls_versions)}")
            
            cipher_count = len(summary.get('cipher_suites_found', []))
            print(f"   Cipher Suites: {cipher_count} found")
            
            # Show PQ assessment
            for port_str, port_data in tls_scan.get('ports', {}).items():
                if port_data.get('success'):
                    pq_assessment = port_data.get('post_quantum_assessment', {})
                    if pq_assessment:
                        print(f"\n   🔒 PQ Assessment (Port {port_str}):")
                        print(f"      Has PQ Ciphers: {pq_assessment.get('has_pq_ciphers', False)}")
                        print(f"      Overall Ready: {pq_assessment.get('overall_assessment', False)}")
                        
                        indicators = pq_assessment.get('pq_indicators', [])
                        if indicators:
                            print(f"      Indicators:")
                            for indicator in indicators:
                                print(f"        • {indicator}")
        else:
            print(f"   ❌ Connection failed")
    
    # PQ test results
    if pq_test:
        print(f"\n🔒 Post-Quantum Testing:")
        print(f"   PQ Support Detected: {'✅ YES' if pq_test.get('pq_support') else '❌ NO'}")
        
        algorithms = pq_test.get('pq_algorithms', [])
        if algorithms:
            print(f"   Supported PQ Algorithms:")
            for alg in algorithms:
                print(f"     • {alg}")
        
        hybrid_support = pq_test.get('hybrid_support', False)
        if hybrid_support:
            print(f"   🔄 Hybrid PQ Support: ✅ YES")
        
        # Show tool-specific results
        tool_results = pq_test.get('tool_results', {})
        for tool, tool_result in tool_results.items():
            if tool_result.get('success'):
                print(f"\n   ✅ {tool.upper()} Results:")
                tool_algorithms = tool_result.get('algorithms', [])
                for alg in tool_algorithms:
                    print(f"     • {alg}")
            else:
                error = tool_result.get('error', 'Unknown error')
                print(f"   ❌ {tool.upper()}: {error}")
    
    elif any(tools_available.values()):
        print(f"\n🔒 Post-Quantum Testing: ❌ Failed to test")
    else:
        print(f"\n🔒 Post-Quantum Testing: ⚠️  No PQ tools available")


def show_installation_guide():
    """Show installation guide for PQ tools."""
    print("""
Post-Quantum TLS Tools Installation Guide
==========================================

To enable comprehensive PQ testing, you need PQ-capable TLS tools:

1. OQS-OpenSSL (Recommended)
   -------------------------
   # Clone and build OQS-OpenSSL
   git clone https://github.com/open-quantum-safe/openssl.git oqs-openssl
   cd oqs-openssl
   ./Configure --prefix=/usr/local/oqs-openssl
   make -j$(nproc)
   sudo make install
   
   # Add to PATH
   export PATH="/usr/local/oqs-openssl/bin:$PATH"

2. OQS-curl
   ---------
   # First install OQS-OpenSSL (above), then:
   git clone https://github.com/open-quantum-safe/curl.git oqs-curl
   cd oqs-curl
   ./configure --with-openssl=/usr/local/oqs-openssl --prefix=/usr/local/oqs-curl
   make -j$(nproc)
   sudo make install
   
   # Add to PATH
   export PATH="/usr/local/oqs-curl/bin:$PATH"

3. Docker Alternative (Easiest)
   ----------------------------
   # Use pre-built OQS Docker image
   docker pull openquantumsafe/curl
   
   # Test with Docker
   docker run --rm openquantumsafe/curl curl --curves kyber512 https://example.com

4. Package Managers
   ----------------
   # Ubuntu/Debian (if available)
   sudo apt update
   sudo apt install liboqs-dev
   
   # macOS with Homebrew
   brew install liboqs

5. Verification
   ------------
   # Test OpenSSL
   openssl ecparam -list_curves | grep -i kyber
   
   # Test curl
   curl --curves help | grep -i kyber

For more information:
- OQS Project: https://openquantumsafe.org/
- OQS-OpenSSL: https://github.com/open-quantum-safe/openssl
- OQS-curl: https://github.com/open-quantum-safe/curl
""")


if __name__ == "__main__":
    main()