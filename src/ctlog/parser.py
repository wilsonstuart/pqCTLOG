"""
Certificate parsing and analysis utilities.
"""
import logging
from datetime import datetime
from typing import Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionNotFound, ExtensionOID, DNSName

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

def parse_ct_log_entry(entry_data: bytes) -> Dict[str, Any]:
    """Parse a CT log entry and extract the certificate.
    
    Args:
        entry_data: Raw CT log entry data
        
    Returns:
        Parsed certificate information or None if parsing fails
    """
    try:
        # The first byte is the version, which we can skip
        if len(entry_data) < 2:
            return None
            
        # Skip the version byte and parse the entry type
        entry_type = entry_data[0]
        
        # Handle different entry types
        if entry_type == 0:  # X509LogEntryType
            # The rest is the actual certificate
            cert_data = entry_data[1:]
            return parse_certificate(cert_data)
            
        elif entry_type == 1:  # PreCertificateEntry
            # For pre-certificates, the structure is:
            # 1. Length of issuer key hash (2 bytes, big-endian)
            # 2. Issuer key hash
            # 3. TBSCertificate data
            if len(entry_data) < 3:  # Need at least 1 byte for issuer key hash length + some data
                logger.warning("Invalid pre-certificate entry: too short")
                return None
                
            # Skip the entry type byte
            entry_data = entry_data[1:]
            
            # Parse the TBSCertificate (the actual pre-certificate)
            try:
                # Extract the TBSCertificate (the rest of the data after issuer key hash)
                # First 2 bytes are the length of the issuer key hash
                issuer_key_hash_len = int.from_bytes(entry_data[:2], byteorder='big')
                if len(entry_data) < 2 + issuer_key_hash_len:
                    logger.warning("Invalid pre-certificate entry: truncated issuer key hash")
                    return None
                    
                # The TBSCertificate comes after the issuer key hash
                tbs_cert_data = entry_data[2 + issuer_key_hash_len:]
                if not tbs_cert_data:
                    logger.warning("No TBSCertificate data in pre-certificate entry")
                    return None
                    
                # Parse the TBSCertificate as a regular certificate
                return parse_certificate(tbs_cert_data)
                
            except Exception as e:
                logger.warning(f"Failed to parse pre-certificate entry: {e}")
                return None
        else:
            logger.warning(f"Unsupported entry type: {entry_type}")
            return None
        
    except Exception as e:
        logger.error(f"Failed to parse CT log entry: {e}")
        return None

def parse_certificate(der_data: bytes) -> Dict[str, Any]:
    """Parse a certificate in DER format and extract relevant information.
    
    Args:
        der_data: Certificate data in DER format or CT log entry
        
    Returns:
        Dictionary containing parsed certificate information or None if parsing fails
    """
    try:
        # First try to parse as a direct certificate
        try:
            cert = x509.load_der_x509_certificate(der_data, default_backend())
        except Exception as e:
            # If that fails, try parsing as a CT log entry
            logger.debug(f"Failed to parse as direct certificate, trying CT log entry: {e}")
            return parse_ct_log_entry(der_data)
    except Exception as e:
        logger.error(f"Failed to parse certificate: {str(e)}")
        return {}
    
    # Get signature algorithm
    sig_algorithm_oid = cert.signature_algorithm_oid
    sig_algorithm_name = sig_algorithm_oid._name  # type: ignore
    
    # Check if the signature algorithm is quantum-vulnerable
    is_quantum_vulnerable = sig_algorithm_name.lower() in (
        alg.lower() for alg in QUANTUM_VULNERABLE_ALGORITHMS
    )
    
    def parse_name(name):
        result = {}
        # Try to parse the DN string if the name object has a rfc4514_string method
        try:
            dn_str = name.rfc4514_string()
            # Parse the DN components
            for part in dn_str.split(','):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip().upper()
                    value = value.strip()
                    
                    # Map common abbreviations to full names
                    if key == 'CN':
                        result['commonName'] = value
                    elif key == 'O':
                        result['organizationName'] = value
                    elif key == 'OU':
                        result['organizationalUnitName'] = value
                    elif key == 'C':
                        result['countryName'] = value
                    elif key == 'ST':
                        result['stateOrProvinceName'] = value
                    elif key == 'L':
                        result['localityName'] = value
                    else:
                        # For any other attributes, use the key as is
                        result[key] = value
        except Exception as e:
            logger.warning(f"Error parsing DN string: {e}")
            # Fall back to the original parsing method
            for attr in name:
                try:
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
                    else:
                        oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                        result[oid_name] = attr.value
                except Exception as attr_error:
                    logger.warning(f"Error parsing name attribute {attr.oid}: {attr_error}")
        
        # If we didn't find any recognized attributes, use the full DN string
        if not result:
            result = {'dn': name.rfc4514_string()}
        return result
    
    # Extract subject information
    subject = parse_name(cert.subject)
    
    # Extract issuer information
    issuer = parse_name(cert.issuer)
    
    # Extract subject alternative names
    san = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = [name.value for name in ext.value if isinstance(name, DNSName)]
    except ExtensionNotFound:
        pass
    
    # Extract key usage and extended key usage
    key_usage = []
    ext_key_usage = []
    
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        key_usage = [k for k, v in ku_ext.value.__dict__.items() 
                    if isinstance(v, bool) and v and not k.startswith('_')]
    except ExtensionNotFound:
        pass
    
    try:
        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        ext_key_usage = [eku._name for eku in eku_ext.value]  # type: ignore
    except (ExtensionNotFound, AttributeError):
        pass
    
    # Check for basic constraints
    is_ca = False
    path_length = None
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bc_ext.value.ca  # type: ignore
        path_length = bc_ext.value.path_length  # type: ignore
    except ExtensionNotFound:
        pass
    
    # Get public key information
    public_key_info = {}
    if cert.public_key():
        public_key = cert.public_key()
        public_key_info['type'] = public_key.__class__.__name__
        
        if hasattr(public_key, 'key_size'):
            public_key_info['key_size'] = public_key.key_size
        
        if hasattr(public_key, 'curve'):
            public_key_info['curve'] = public_key.curve.name  # type: ignore
    
    # Check certificate validity
    now = datetime.utcnow()
    is_valid = cert.not_valid_before <= now <= cert.not_valid_after
    
    # Check for self-signed certificate
    is_self_signed = cert.issuer == cert.subject
    
    # Format dates consistently
    not_before_iso = cert.not_valid_before.isoformat()
    not_after_iso = cert.not_valid_after.isoformat()
    
    # Prepare result with consistent validity fields
    result = {
        'serial_number': str(cert.serial_number),
        'version': cert.version.name,
        'signature_algorithm': {
            'name': sig_algorithm_name,
            'is_quantum_vulnerable': is_quantum_vulnerable,
            'is_post_quantum': False,  # Default value, can be updated later
            'pq_algorithm_type': None,  # Default value, can be updated later
            'security_level': None      # Default value, can be updated later
        },
        'issuer': issuer,
        'subject': subject,
        'subject_alternative_names': san,
        'validity': {
            'not_before': not_before_iso,
            'not_after': not_after_iso,
            'start': not_before_iso,  # For backward compatibility
            'end': not_after_iso,     # For backward compatibility
            'is_valid': is_valid,
        },
        'key_usage': key_usage,
        'extended_key_usage': ext_key_usage,
        'basic_constraints': {
            'is_ca': is_ca,
            'path_length': path_length,
        },
        'public_key': public_key_info,
        'is_self_signed': is_self_signed,
        'extensions': {},
    }
    
    # Add custom extensions
    for ext in cert.extensions:
        try:
            if isinstance(ext.value, x509.UnrecognizedExtension):
                result['extensions'][ext.oid.dotted_string] = {
                    'critical': ext.critical,
                    'value': ext.value.value.hex(),
                }
        except Exception as e:
            logger.debug(f"Failed to process extension {ext.oid._name}: {str(e)}")
    
    return result
