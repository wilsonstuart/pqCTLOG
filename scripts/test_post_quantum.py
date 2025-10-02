#!/usr/bin/env python3
"""
Test script for post-quantum cipher detection.
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.config import load_config
from src.scanner.tls_scanner import TLSScanner


def test_post_quantum_detection():
    """Test post-quantum cipher detection logic."""
    config = load_config()
    scanner = TLSScanner(config)
    
    print("Testing Post-Quantum Cipher Detection")
    print("=" * 50)
    
    # Test cases for post-quantum ciphers
    pq_test_cases = [
        "TLS_KYBER_512_AES_128_GCM_SHA256",
        "TLS_FALCON_512_AES_256_GCM_SHA384", 
        "TLS_DILITHIUM_2_CHACHA20_POLY1305_SHA256",
        "ECDHE-KYBER512-AES256-GCM-SHA384",
        "DHE-FALCON1024-AES128-GCM-SHA256",
        "TLS_SPHINCS_SHA256_128F_AES_128_GCM_SHA256",
        "TLS_NTRU_HPS_2048_509_AES_256_GCM_SHA384",
        "TLS_FRODO_640_AES_128_GCM_SHA256",
        "TLS_SABER_LIGHTSABER_AES_256_GCM_SHA384"
    ]
    
    # Test cases for regular ciphers
    regular_test_cases = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384", 
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384"
    ]
    
    print("\n🔒 Post-Quantum Ciphers (should be detected as PQ-ready):")
    for cipher in pq_test_cases:
        is_pq = scanner._is_post_quantum_cipher(cipher)
        status = "✅ DETECTED" if is_pq else "❌ MISSED"
        print(f"  {status} {cipher}")
    
    print("\n🔓 Regular Ciphers (should NOT be detected as PQ-ready):")
    for cipher in regular_test_cases:
        is_pq = scanner._is_post_quantum_cipher(cipher)
        status = "❌ FALSE POSITIVE" if is_pq else "✅ CORRECT"
        print(f"  {status} {cipher}")
    
    print(f"\nConfigured PQ cipher patterns: {scanner.post_quantum_ciphers}")


def test_mock_scan_result():
    """Test post-quantum readiness assessment with mock scan results."""
    config = load_config()
    scanner = TLSScanner(config)
    
    print("\n" + "=" * 50)
    print("Testing Post-Quantum Readiness Assessment")
    print("=" * 50)
    
    # Mock scan result with regular ciphers
    regular_result = {
        'cipher_suites': [
            {
                'name': 'TLS_AES_256_GCM_SHA384',
                'is_post_quantum': False
            },
            {
                'name': 'ECDHE-RSA-AES256-GCM-SHA384', 
                'is_post_quantum': False
            }
        ]
    }
    
    # Mock scan result with post-quantum ciphers
    pq_result = {
        'cipher_suites': [
            {
                'name': 'TLS_KYBER_512_AES_128_GCM_SHA256',
                'is_post_quantum': True
            },
            {
                'name': 'TLS_AES_256_GCM_SHA384',
                'is_post_quantum': False
            }
        ]
    }
    
    regular_pq_ready = scanner._check_post_quantum_readiness(regular_result)
    pq_ready = scanner._check_post_quantum_readiness(pq_result)
    
    print(f"\nRegular ciphers only: PQ-ready = {regular_pq_ready} (should be False)")
    print(f"Mixed with PQ ciphers: PQ-ready = {pq_ready} (should be True)")


def test_cipher_security_assessment():
    """Test the updated cipher security assessment."""
    config = load_config()
    scanner = TLSScanner(config)
    
    print("\n" + "=" * 50)
    print("Testing Cipher Security Assessment")
    print("=" * 50)
    
    test_ciphers = [
        # Should be secure
        ("TLS_AES_256_GCM_SHA384", "secure"),
        ("TLS_AES_128_GCM_SHA256", "secure"), 
        ("TLS_CHACHA20_POLY1305_SHA256", "secure"),
        ("ECDHE-RSA-AES256-GCM-SHA384", "secure"),
        ("ECDHE-ECDSA-AES128-SHA256", "secure"),
        
        # Should be weak
        ("ECDHE-RSA-AES256-CBC-SHA1", "weak"),
        ("DHE-RSA-3DES-EDE-CBC-SHA", "weak"),
        ("ADH-AES256-GCM-SHA384", "weak"),
        
        # Should be insecure
        ("RC4-MD5", "insecure"),
        ("DES-CBC-SHA", "insecure"),
        ("NULL-SHA", "insecure"),
        ("EXPORT-RC4-40-MD5", "insecure")
    ]
    
    print("\nCipher Security Assessment:")
    for cipher, expected in test_ciphers:
        actual = scanner._assess_cipher_security(cipher)
        status = "✅" if actual == expected else "❌"
        print(f"  {status} {cipher:<35} Expected: {expected:<8} Got: {actual}")


if __name__ == "__main__":
    test_post_quantum_detection()
    test_mock_scan_result()
    test_cipher_security_assessment()