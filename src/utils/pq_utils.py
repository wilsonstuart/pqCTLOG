"""Utilities for Post-Quantum cryptography analysis."""
from datetime import datetime
from typing import Dict, Optional

# Known Post-Quantum signature algorithms and their properties
PQ_SIGNATURE_ALGORITHMS = {
    # NIST PQC Round 3 Finalists and Alternates
    'DILITHIUM': {
        'is_pq': True,
        'type': 'lattice',
        'security_level': 128,  # Minimum security level
        'compliance_level': 'pq_secure'
    },
    'FALCON': {
        'is_pq': True,
        'type': 'lattice',
        'security_level': 128,
        'compliance_level': 'pq_secure'
    },
    'SPHINCS+': {
        'is_pq': True,
        'type': 'hash',
        'security_level': 128,
        'compliance_level': 'pq_secure'
    },
    'RAINBOW': {
        'is_pq': True,
        'type': 'multivariate',
        'security_level': 128,
        'compliance_level': 'pq_secure'
    },
    
    # Hybrid schemes (PQ + classical)
    'ECDSA_DILITHIUM': {
        'is_pq': True,
        'type': 'hybrid',
        'security_level': 128,
        'compliance_level': 'hybrid'
    },
    'RSA_DILITHIUM': {
        'is_pq': True,
        'type': 'hybrid',
        'security_level': 128,
        'compliance_level': 'hybrid'
    },
    
    # Classical algorithms (for comparison)
    'RSA': {
        'is_pq': False,
        'type': 'classical',
        'security_level': 0,  # Will be set based on key size
        'compliance_level': 'classical'
    },
    'ECDSA': {
        'is_pq': False,
        'type': 'classical',
        'security_level': 0,  # Will be set based on curve
        'compliance_level': 'classical'
    },
    'DSA': {
        'is_pq': False,
        'type': 'classical',
        'security_level': 0,  # Will be set based on key size
        'compliance_level': 'classical'
    }
}

def get_algorithm_info(algorithm_name: str, key_size: Optional[int] = None) -> Dict:
    """
    Get information about a cryptographic algorithm.
    
    Args:
        algorithm_name: Name of the algorithm (case-insensitive)
        key_size: Key size in bits (for classical algorithms)
        
    Returns:
        Dictionary with algorithm information
    """
    algorithm_name = algorithm_name.upper()
    
    # Check for exact match first
    for name, info in PQ_SIGNATURE_ALGORITHMS.items():
        if name in algorithm_name:
            result = info.copy()
            
            # For classical algorithms, update security level based on key size
            if not result['is_pq'] and key_size:
                if 'RSA' in name or 'DSA' in name:
                    if key_size >= 3072:
                        result['security_level'] = 128
                    elif key_size >= 2048:
                        result['security_level'] = 112
                    else:
                        result['security_level'] = 80
                        result['compliance_level'] = 'deprecated'
                elif 'ECDSA' in name:
                    if key_size >= 384:  # P-384 or larger
                        result['security_level'] = 192
                    elif key_size >= 256:  # P-256
                        result['security_level'] = 128
                    else:
                        result['security_level'] = 80
                        result['compliance_level'] = 'deprecated'
            
            return result
    
    # Default to classical if not found
    return {
        'is_pq': False,
        'type': 'classical',
        'security_level': 0,
        'compliance_level': 'classical'
    }

def analyze_certificate(cert_data: Dict) -> Dict:
    """
    Analyze a certificate for Post-Quantum compliance.
    
    Args:
        cert_data: Dictionary containing certificate information
        
    Returns:
        Dictionary with PQ compliance information
    """
    signature_algorithm = cert_data.get('signature_algorithm', {}).get('name', '').upper()
    public_key_size = cert_data.get('public_key_size')
    
    # Get algorithm information
    algo_info = get_algorithm_info(signature_algorithm, public_key_size)
    
    # Check if the certificate is expired
    not_after = cert_data.get('not_after')
    is_expired = False
    if not_after:
        if isinstance(not_after, str):
            try:
                not_after_dt = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                is_expired = datetime.now(not_after_dt.tzinfo) > not_after_dt
            except (ValueError, AttributeError):
                pass
    
    # Determine overall compliance
    compliance_level = algo_info['compliance_level']
    if is_expired:
        compliance_level = 'expired'
    
    return {
        'signature_algorithm': {
            'name': signature_algorithm,
            'is_quantum_vulnerable': not algo_info['is_pq'],
            'is_post_quantum': algo_info['is_pq'],
            'pq_algorithm_type': algo_info['type'] if algo_info['is_pq'] else None,
            'security_level': algo_info['security_level']
        },
        'compliance': {
            'post_quantum': algo_info['is_pq'],
            'compliance_level': compliance_level,
            'last_verified': datetime.utcnow().isoformat() + 'Z'
        }
    }
