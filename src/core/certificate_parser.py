"""
Consolidated certificate parsing utilities.
"""
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .utils import safe_parse_date

logger = logging.getLogger(__name__)

# Known quantum-vulnerable signature algorithms
QUANTUM_VULNERABLE_ALGORITHMS = {
    'rsaEncryption',
    'sha1WithRSAEncryption', 
    'sha256WithRSAEncryption',
    'sha384WithRSAEncryption',
    'sha512WithRSAEncryption',
    'ecdsa-with-SHA1',
    'ecdsa-with-SHA256',
    'ecdsa-with-SHA384',
    'ecdsa-with-SHA512',
}

# Known quantum-resistant signature algorithms
QUANTUM_RESISTANT_ALGORITHMS = {
    'id-dilithium2',
    'id-dilithium3', 
    'id-dilithium5',
    'sphincsharaka128frobust',
    'sphincssha256128frobust',
    'falcon-512',
    'falcon-1024',
}


class CertificateParser:
    """Unified certificate parser with multiple backend support."""
    
    def __init__(self):
        self.crypto_available = self._check_crypto_availability()
    
    def _check_crypto_availability(self) -> bool:
        """Check if cryptography library is available."""
        try:
            import cryptography
            return True
        except ImportError:
            logger.warning("cryptography library not available, using fallback parsing")
            return False
    
    def parse_certificate_pem(self, cert_pem: str, cert_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Parse a PEM certificate and extract relevant details."""
        if not cert_pem or '-----BEGIN CERTIFICATE-----' not in cert_pem:
            logger.warning("Invalid PEM certificate format")
            return None
        
        if self.crypto_available:
            return self._parse_with_cryptography(cert_pem, cert_id)
        else:
            return self._parse_with_openssl(cert_pem, cert_id)
    
    def _parse_with_cryptography(self, cert_pem: str, cert_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Parse certificate using the cryptography library."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            
            # Clean up PEM data
            cert_pem = self._clean_pem_data(cert_pem)
            
            # Load certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
            
            # Extract basic information
            result = {
                'id': cert_id,
                'serial_number': str(cert.serial_number),
                'version': f"X.509v{cert.version.value}",
                'subject': self._parse_name_cryptography(cert.subject),
                'issuer': self._parse_name_cryptography(cert.issuer),
                'validity': self._parse_validity_cryptography(cert),
                'public_key': self._extract_public_key_info_cryptography(cert.public_key()),
                'signature_algorithm': self._parse_signature_algorithm(cert),
                'extensions': self._parse_extensions_cryptography(cert),
                'is_self_signed': cert.issuer == cert.subject,
            }
            
            # Add fingerprints
            try:
                result['fingerprints'] = {
                    'sha1': cert.fingerprint(hashes.SHA1()).hex(),
                    'sha256': cert.fingerprint(hashes.SHA256()).hex()
                }
            except Exception as e:
                logger.debug(f"Error calculating fingerprints: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing certificate with cryptography: {e}")
            return None
    
    def _parse_with_openssl(self, cert_pem: str, cert_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Fallback parsing using OpenSSL library."""
        try:
            import OpenSSL.crypto
            
            cert_pem = self._clean_pem_data(cert_pem)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem.encode('utf-8'))
            
            result = {
                'id': cert_id,
                'serial_number': str(cert.get_serial_number()),
                'version': f"X.509v{cert.get_version() + 1}",
                'subject': self._parse_name_openssl(cert.get_subject()),
                'issuer': self._parse_name_openssl(cert.get_issuer()),
                'validity': self._parse_validity_openssl(cert),
                'public_key': self._extract_public_key_info_openssl(cert.get_pubkey()),
                'signature_algorithm': {'name': cert.get_signature_algorithm().decode('utf-8')},
                'extensions': {},
                'is_self_signed': cert.get_issuer() == cert.get_subject(),
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing certificate with OpenSSL: {e}")
            return None
    
    def _clean_pem_data(self, cert_pem: str) -> str:
        """Clean and normalize PEM certificate data."""
        cert_pem = cert_pem.strip()
        
        if not cert_pem.startswith('-----BEGIN CERTIFICATE-----'):
            cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_pem}"
        if not cert_pem.endswith('-----END CERTIFICATE-----'):
            cert_pem = f"{cert_pem}\n-----END CERTIFICATE-----"
        
        return cert_pem
    
    def _parse_name_cryptography(self, name) -> Dict[str, str]:
        """Parse X.509 name using cryptography library."""
        result = {}
        
        try:
            from cryptography import x509
            
            for attr in name:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    result['commonName'] = attr.value
                elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                    result['organizationName'] = attr.value
                elif attr.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                    result['organizationalUnitName'] = attr.value
                elif attr.oid == x509.NameOID.COUNTRY_NAME:
                    result['countryName'] = attr.value
                elif attr.oid == x509.NameOID.STATE_OR_PROVINCE_NAME:
                    result['stateOrProvinceName'] = attr.value
                elif attr.oid == x509.NameOID.LOCALITY_NAME:
                    result['localityName'] = attr.value
                elif attr.oid == x509.NameOID.EMAIL_ADDRESS:
                    result['emailAddress'] = attr.value
                else:
                    # Use OID name if available, otherwise dotted string
                    oid_name = getattr(attr.oid, '_name', str(attr.oid))
                    result[oid_name] = attr.value
                    
        except Exception as e:
            logger.warning(f"Error parsing name: {e}")
            result = {'dn': name.rfc4514_string()}
        
        return result
    
    def _parse_name_openssl(self, name) -> Dict[str, str]:
        """Parse X.509 name using OpenSSL library."""
        result = {}
        
        try:
            for component in name.get_components():
                key = component[0].decode('utf-8')
                value = component[1].decode('utf-8')
                
                # Map common abbreviations
                key_mapping = {
                    'CN': 'commonName',
                    'O': 'organizationName', 
                    'OU': 'organizationalUnitName',
                    'C': 'countryName',
                    'ST': 'stateOrProvinceName',
                    'L': 'localityName',
                    'emailAddress': 'emailAddress'
                }
                
                result[key_mapping.get(key, key)] = value
                
        except Exception as e:
            logger.warning(f"Error parsing OpenSSL name: {e}")
        
        return result
    
    def _parse_validity_cryptography(self, cert) -> Dict[str, Any]:
        """Parse certificate validity period using cryptography."""
        try:
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            
            now = datetime.utcnow()
            is_valid = not_before <= now <= not_after
            days_remaining = max(0, (not_after - now).days) if not_after > now else 0
            
            return {
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'is_valid': is_valid,
                'days_remaining': days_remaining
            }
        except Exception as e:
            logger.warning(f"Error parsing validity: {e}")
            return {}
    
    def _parse_validity_openssl(self, cert) -> Dict[str, Any]:
        """Parse certificate validity period using OpenSSL."""
        try:
            not_before = datetime.strptime(cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
            
            now = datetime.utcnow()
            is_valid = not_before <= now <= not_after
            days_remaining = max(0, (not_after - now).days) if not_after > now else 0
            
            return {
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'is_valid': is_valid,
                'days_remaining': days_remaining
            }
        except Exception as e:
            logger.warning(f"Error parsing OpenSSL validity: {e}")
            return {}
    
    def _extract_public_key_info_cryptography(self, pubkey) -> Dict[str, Any]:
        """Extract public key information using cryptography."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
            
            if isinstance(pubkey, rsa.RSAPublicKey):
                return {
                    'type': 'RSA',
                    'size': pubkey.key_size,
                    'details': {'modulus_bits': pubkey.key_size}
                }
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                return {
                    'type': 'EC',
                    'size': pubkey.key_size,
                    'details': {'curve': pubkey.curve.name}
                }
            elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                is_ed25519 = isinstance(pubkey, ed25519.Ed25519PublicKey)
                return {
                    'type': 'EdDSA',
                    'size': 255 if is_ed25519 else 448,
                    'details': {'algorithm': 'Ed25519' if is_ed25519 else 'Ed448'}
                }
            elif isinstance(pubkey, dsa.DSAPublicKey):
                return {
                    'type': 'DSA',
                    'size': pubkey.key_size,
                    'details': {}
                }
            else:
                return {'type': 'Unknown', 'size': 0, 'details': {}}
                
        except Exception as e:
            logger.warning(f"Error extracting public key info: {e}")
            return {'type': 'Unknown', 'size': 0, 'details': {}}
    
    def _extract_public_key_info_openssl(self, pubkey) -> Dict[str, Any]:
        """Extract public key information using OpenSSL."""
        try:
            import OpenSSL.crypto
            
            key_type_map = {
                OpenSSL.crypto.TYPE_RSA: 'RSA',
                OpenSSL.crypto.TYPE_DSA: 'DSA'
            }
            
            key_type = key_type_map.get(pubkey.type(), 'Unknown')
            
            return {
                'type': key_type,
                'size': pubkey.bits(),
                'details': {}
            }
        except Exception as e:
            logger.warning(f"Error extracting OpenSSL public key info: {e}")
            return {'type': 'Unknown', 'size': 0, 'details': {}}
    
    def _parse_signature_algorithm(self, cert) -> Dict[str, Any]:
        """Parse signature algorithm information."""
        try:
            sig_alg_name = cert.signature_algorithm_oid._name
            
            is_quantum_vulnerable = sig_alg_name.lower() in (
                alg.lower() for alg in QUANTUM_VULNERABLE_ALGORITHMS
            )
            is_post_quantum = sig_alg_name.lower() in (
                alg.lower() for alg in QUANTUM_RESISTANT_ALGORITHMS
            )
            
            return {
                'name': sig_alg_name,
                'is_quantum_vulnerable': is_quantum_vulnerable,
                'is_post_quantum': is_post_quantum,
                'pq_algorithm_type': None,
                'security_level': None
            }
        except Exception as e:
            logger.warning(f"Error parsing signature algorithm: {e}")
            return {
                'name': 'unknown',
                'is_quantum_vulnerable': False,
                'is_post_quantum': False,
                'pq_algorithm_type': None,
                'security_level': None
            }
    
    def _parse_extensions_cryptography(self, cert) -> Dict[str, Any]:
        """Parse certificate extensions using cryptography."""
        extensions = {}
        
        try:
            from cryptography import x509
            
            for ext in cert.extensions:
                try:
                    ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                    
                    if ext_name == 'subjectAltName':
                        extensions[ext_name] = [name.value for name in ext.value 
                                              if isinstance(name, x509.DNSName)]
                    elif ext_name == 'keyUsage':
                        extensions[ext_name] = [k for k, v in ext.value.__dict__.items() 
                                              if isinstance(v, bool) and v and not k.startswith('_')]
                    elif ext_name == 'extendedKeyUsage':
                        extensions[ext_name] = [ku._name for ku in ext.value]
                    else:
                        extensions[ext_name] = str(ext.value)
                        
                except Exception as e:
                    logger.debug(f"Error processing extension {ext_name}: {e}")
                    
        except Exception as e:
            logger.warning(f"Error parsing extensions: {e}")
        
        return extensions


# Global parser instance
certificate_parser = CertificateParser()


def parse_certificate_pem(cert_pem: str, cert_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Parse a PEM certificate using the global parser."""
    return certificate_parser.parse_certificate_pem(cert_pem, cert_id)