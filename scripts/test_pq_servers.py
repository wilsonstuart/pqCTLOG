#!/usr/bin/env python3
"""
Test script to check known servers that might support post-quantum cryptography.
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import load_config
from src.scanner.tls_scanner import TLSScanner


def test_known_pq_servers():
    """Test servers that are known to experiment with post-quantum crypto."""
    config = load_config()
    scanner = TLSScanner(config)
    
    # Known servers that might support post-quantum (experimental)
    test_servers = [
        # Google's experimental servers
        "pq.googleapis.com",
        "pq-test.googleapis.com", 
        
        # Cloudflare's experimental servers
        "pq.cloudflareresearch.com",
        "tls13-pq.cloudflareresearch.com",
        
        # NIST/academic test servers
        "pqc-test.nist.gov",
        "pqtls.org",
        
        # Open Quantum Safe test servers
        "test.openquantumsafe.org",
        "oqs-test.com",
        
        # Some regular servers for comparison
        "google.com",
        "cloudflare.com"
    ]
    
    print("Testing servers for Post-Quantum TLS support")
    print("=" * 60)
    print("Note: Most of these servers may not exist or may not support PQ crypto")
    print("This is mainly to test our detection logic with real TLS connections")
    print("=" * 60)
    
    for server in test_servers:
        print(f"\n🔍 Testing: {server}")
        try:
            result = scanner.scan_domain(server)
            if result and result.get('summary', {}).get('successful_connections', 0) > 0:
                summary = result['summary']
                pq_ready = summary.get('post_quantum_ready', False)
                tls_versions = summary.get('tls_versions_supported', [])
                cipher_count = len(summary.get('cipher_suites_found', []))
                
                print(f"  ✅ Connection successful")
                print(f"  📋 TLS versions: {', '.join(tls_versions) if tls_versions else 'None'}")
                print(f"  🔐 Cipher suites: {cipher_count} found")
                print(f"  🔒 Post-quantum ready: {'YES' if pq_ready else 'NO'}")
                
                # Show cipher details if PQ ready
                if pq_ready:
                    print("  🎉 POST-QUANTUM CRYPTO DETECTED!")
                    for port_str, port_data in result.get('ports', {}).items():
                        if port_data.get('success'):
                            for cipher in port_data.get('cipher_suites', []):
                                if cipher.get('is_post_quantum'):
                                    print(f"    🔒 PQ Cipher: {cipher['name']}")
                
                # Show any security issues
                issues = summary.get('security_issues', [])
                if issues:
                    print(f"  ⚠️  Issues: {len(issues)}")
                    for issue in issues[:2]:  # Show first 2
                        print(f"    - {issue}")
            else:
                error = result.get('error') if result else 'Unknown error'
                print(f"  ❌ Connection failed: {error}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")


def test_with_custom_pq_config():
    """Test with expanded post-quantum cipher patterns."""
    config = load_config()
    
    # Add more PQ cipher patterns for testing
    additional_pq_patterns = [
        'MLKEM',      # ML-KEM (NIST standardized Kyber)
        'MLDSA',      # ML-DSA (NIST standardized Dilithium)
        'SLHDSA',     # SLH-DSA (NIST standardized SPHINCS+)
        'BIKE',       # BIKE
        'HQC',        # HQC
        'CLASSIC_MCELIECE',  # Classic McEliece
        'XMSS',       # XMSS
        'LMS'         # LMS
    ]
    
    config.tls_scanner.post_quantum_ciphers.extend(additional_pq_patterns)
    scanner = TLSScanner(config)
    
    print(f"\n" + "=" * 60)
    print("Testing with expanded PQ cipher patterns")
    print("=" * 60)
    print(f"PQ patterns: {scanner.post_quantum_ciphers}")
    
    # Test some hypothetical future cipher names
    future_ciphers = [
        "TLS_MLKEM_768_AES_256_GCM_SHA384",
        "TLS_MLDSA_65_CHACHA20_POLY1305_SHA256", 
        "ECDHE-MLKEM1024-AES256-GCM-SHA384",
        "TLS_SLHDSA_128F_AES_128_GCM_SHA256",
        "TLS_BIKE_L1_AES_256_GCM_SHA384"
    ]
    
    print("\nTesting future PQ cipher detection:")
    for cipher in future_ciphers:
        is_pq = scanner._is_post_quantum_cipher(cipher)
        status = "✅ DETECTED" if is_pq else "❌ MISSED"
        print(f"  {status} {cipher}")


if __name__ == "__main__":
    test_known_pq_servers()
    test_with_custom_pq_config()