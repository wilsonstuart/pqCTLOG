#!/usr/bin/env python3
"""
Test Cloudflare sites for post-quantum indicators.
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import load_config
from src.scanner.tls_scanner import TLSScanner


def test_cloudflare_sites():
    """Test Cloudflare-protected sites for PQ indicators."""
    config = load_config()
    scanner = TLSScanner(config)
    
    # Known Cloudflare sites
    cloudflare_sites = [
        "regdata.fca.org.uk",
        "cloudflare.com", 
        "blog.cloudflare.com",
        "www.cloudflare.com",
        "dash.cloudflare.com"
    ]
    
    print("Testing Cloudflare Sites for Post-Quantum Indicators")
    print("=" * 60)
    print("Note: These sites may support hybrid PQ key exchange, but our")
    print("Python client cannot negotiate PQ algorithms, so we look for indicators.")
    print("=" * 60)
    
    for site in cloudflare_sites:
        print(f"\n🔍 Testing: {site}")
        try:
            result = scanner.scan_domain(site)
            if result and result.get('summary', {}).get('successful_connections', 0) > 0:
                
                # Check each port's results
                for port_str, port_data in result.get('ports', {}).items():
                    if port_data.get('success'):
                        print(f"\n  📡 Port {port_str}:")
                        
                        # Show certificate info
                        cert_info = port_data.get('certificate_info', {})
                        if cert_info:
                            issuer = cert_info.get('issuer', {})
                            subject = cert_info.get('subject', {})
                            print(f"    📜 Subject: {subject.get('CN', 'Unknown')}")
                            print(f"    🏢 Issuer: {issuer.get('CN', 'Unknown')}")
                        
                        # Show TLS versions
                        tls_versions = port_data.get('tls_versions', {})
                        supported_versions = [v for v, supported in tls_versions.items() if supported]
                        print(f"    🔐 TLS Versions: {', '.join(supported_versions)}")
                        
                        # Show cipher suites
                        cipher_suites = port_data.get('cipher_suites', [])
                        print(f"    🔑 Cipher Suites: {len(cipher_suites)} found")
                        for cipher in cipher_suites:
                            security = cipher.get('security_level', 'unknown')
                            print(f"      - {cipher['name']} ({security}, {cipher.get('bits', 0)} bits)")
                        
                        # Show PQ assessment
                        pq_assessment = port_data.get('post_quantum_assessment', {})
                        if pq_assessment:
                            print(f"\n    🔒 Post-Quantum Assessment:")
                            print(f"      Has PQ Ciphers: {pq_assessment.get('has_pq_ciphers', False)}")
                            print(f"      Overall Ready: {pq_assessment.get('overall_assessment', False)}")
                            
                            indicators = pq_assessment.get('pq_indicators', [])
                            if indicators:
                                print(f"      🔍 PQ Indicators:")
                                for indicator in indicators:
                                    print(f"        • {indicator}")
                            
                            limitations = pq_assessment.get('limitations', [])
                            if limitations:
                                print(f"      ⚠️  Limitations:")
                                for limitation in limitations:
                                    print(f"        • {limitation}")
                        
                        # Show security issues
                        issues = port_data.get('security_issues', [])
                        if issues:
                            print(f"    ⚠️  Security Issues:")
                            for issue in issues:
                                print(f"      - {issue}")
                
            else:
                error = result.get('error') if result else 'Unknown error'
                print(f"  ❌ Connection failed: {error}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")


def explain_pq_limitations():
    """Explain the limitations of current PQ detection."""
    print("\n" + "=" * 60)
    print("Understanding Post-Quantum Detection Limitations")
    print("=" * 60)
    
    print("""
🔍 What we CAN detect:
  • Explicit PQ cipher suite names (rare in production)
  • TLS 1.3 support (prerequisite for most PQ)
  • ECDHE support (used in hybrid PQ)
  • Cloudflare/Google certificates (known PQ experimenters)

❌ What we CANNOT detect:
  • Hybrid PQ key exchange (requires PQ-capable client)
  • Server's willingness to negotiate PQ with capable clients
  • Actual PQ algorithms used in key exchange
  • PQ certificate signatures (need full cert analysis)

🌐 Real-world PQ deployment:
  • Most PQ is "hybrid" - combines classical + PQ algorithms
  • Servers negotiate PQ only with PQ-capable clients
  • Python's ssl module doesn't support PQ yet
  • Need specialized tools like BoringSSL or OpenSSL 3.x with PQ

🔧 To truly test PQ support:
  • Use curl with PQ-enabled OpenSSL build
  • Use specialized PQ TLS testing tools
  • Check server documentation/announcements
  • Monitor TLS handshake with Wireshark + PQ-capable client

💡 Our scanner provides:
  • Best-effort detection with current limitations
  • Indicators of potential PQ readiness
  • Clear documentation of what we can/cannot see
    """)


if __name__ == "__main__":
    test_cloudflare_sites()
    explain_pq_limitations()