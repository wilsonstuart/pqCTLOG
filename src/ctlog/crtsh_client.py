"""
crt.sh client for searching certificates.
"""
from __future__ import annotations

import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Set up logging
logger = logging.getLogger(__name__)

# Check if cryptography is available
CRYPTO_AVAILABLE = False
if True:  # Keep imports for type checking
    try:
        import importlib.util
        if importlib.util.find_spec('cryptography') is not None:
            # Only import if needed
            CRYPTO_AVAILABLE = True
    except ImportError:
        logger = logging.getLogger(__name__)
        logger.warning("cryptography module not available. Using fallback DN parsing.")

class CRTshError(Exception):
    """Base exception for crt.sh related errors."""
    pass

class CRTshConnectionError(CRTshError):
    """Raised when there are connection issues with crt.sh."""
    pass

class CRTshRateLimitError(CRTshError):
    """Raised when rate limited by crt.sh."""
    pass

class CRTshNotFoundError(CRTshError):
    """Raised when a certificate is not found on crt.sh."""
    pass

class CRTshClient:
    """Client for interacting with the crt.sh certificate transparency log."""
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self, max_retries: int = 3, backoff_factor: float = 1.0, 
                 timeout: int = 30, verify_ssl: bool = True, 
                 rate_limit_delay: float = 1.0):
        """
        Initialize the CRTshClient.
        
        Args:
            max_retries: Maximum number of retry attempts for failed requests
            backoff_factor: Base factor for exponential backoff between retries
                          (in seconds)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            rate_limit_delay: Base delay between requests to avoid rate limiting
                            (in seconds)
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.rate_limit_delay = rate_limit_delay
        
        # Configure session with retry strategy
        self.session = self._create_session()
        
        # Add rate limiting delay between requests
        self.last_request_time = 0
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy."""
        session = requests.Session()
        
        # Configure retry strategy with more conservative defaults
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            respect_retry_after_header=True
        )
        
        # Mount the retry strategy to both http and https
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
        
    def _rate_limit(self) -> None:
        """
        Enforce rate limiting between requests to avoid hitting crt.sh rate limits.
        
        This implements a simple token bucket algorithm with jitter to prevent
        thundering herd problems when multiple instances run simultaneously.
        """
        now = time.monotonic()
        elapsed = now - getattr(self, '_last_request_time', 0)
        
        # Calculate sleep time with jitter (add up to 20% random delay)
        sleep_time = max(0, self.rate_limit_delay - elapsed) * (0.8 + 0.4 * random.random())
        
        if sleep_time > 0:
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
            
        self._last_request_time = time.monotonic()
    
    def search_certificates(self, dns_name: str, match: str = "%", exclude_expired: bool = False) -> List[Dict]:
        """Search for certificates by DNS name using crt.sh.
        
        Args:
            dns_name: Domain name to search for
            match: SQL LIKE pattern match (%% for wildcard)
            exclude_expired: If True, exclude expired certificates
            
        Returns:
            List of certificate information dictionaries
        """
        logger = logging.getLogger('pqctlog.crtsh')
        
        try:
            # Apply rate limiting before request
            self._rate_limit()
            
            # Build the API URL
            url = f"{self.BASE_URL}/"
            params = {
                'q': f'%.{dns_name}',
                'output': 'json',
                'exclude': 'expired' if exclude_expired else ''
            }
            
            # Make the request
            logger.debug(f"Searching crt.sh for certificates matching: {dns_name}")
            response = self._make_request(url, params=params)
            
            if not response:
                logger.warning("No response from crt.sh")
                return []
            
            try:
                # Parse the JSON response
                certificates = response.json()
                
                if not isinstance(certificates, list):
                    logger.warning(f"Unexpected response format. Expected list, got {type(certificates)}")
                    if isinstance(certificates, dict):
                        if 'certificates' in certificates:
                            certificates = certificates['certificates']
                        else:
                            # Try to find any list in the response
                            list_values = [v for v in certificates.values() if isinstance(v, list)]
                            if list_values:
                                certificates = list_values[0]
                                logger.info(f"Extracted results from response dict: {len(certificates)} items")
                            else:
                                logger.warning("No list found in response dictionary")
                                return []
                    else:
                        logger.warning(f"Unexpected response type: {type(certificates)}")
                        return []
                
                logger.info(f"Found {len(certificates)} certificates matching {dns_name}")
                
                # Process each certificate through _process_certificate
                processed_certificates = []
                for cert in certificates:
                    try:
                        # Add the raw data for reference
                        cert['raw'] = cert.copy()
                        
                        # Process the certificate
                        processed = self._process_certificate(cert)
                        if processed:
                            # Add the processed certificate to our results
                            processed_certificates.append(processed)
                            
                    except Exception as e:
                        logger.error(f"Error processing certificate {cert.get('id')}: {e}")
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Problematic certificate data: {cert}")
                        continue
                
                logger.info(f"Successfully processed {len(processed_certificates)} certificates")
                return processed_certificates
                
            except ValueError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                logger.error(f"Response content: {response.text}")
                raise CRTshError(f"Invalid JSON response: {e}")
                
        except Exception as e:
            logger.error(f"Error searching certificates: {e}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Full error details:")
            raise CRTshError(f"Failed to search certificates: {e}")
            
        return []
    
    def _get_certificate_download(self, cert_id: int) -> Optional[Dict[str, Any]]:
        """
        Download and parse a certificate directly from crt.sh.
        
        This method uses the ?d=cert_id endpoint to get the raw certificate in PEM format
        and parses it to extract relevant details.
        
        Args:
            cert_id: The certificate ID to download
            
        Returns:
            Dictionary with certificate details or None if download/parsing fails
        """
        try:
            logger.debug(f"Downloading certificate for ID: {cert_id}")
            
            # First try to get the certificate in DER format which is more reliable
            try:
                response = self._make_request(
                    f"{self.BASE_URL}/crt/der/{cert_id}",
                    stream=True,
                    headers={'Accept': 'application/pkix-cert'},
                    timeout=self.timeout
                )
                cert_der = response.content
                cert_pem = self._der_to_pem(cert_der)
            except Exception as der_error:
                logger.debug(f"DER download failed, falling back to PEM: {str(der_error)}")
                # Fall back to PEM format if DER fails
                response = self._make_request(
                    f"{self.BASE_URL}/?d={cert_id}",
                    stream=True,
                    headers={'Accept': 'application/x-pem-file'},
                    timeout=self.timeout
                )
                cert_pem = response.text.strip()
            
            # Basic validation that this looks like a certificate
            if not cert_pem or '-----BEGIN CERTIFICATE-----' not in cert_pem:
                logger.warning(f"Response does not appear to be a valid PEM certificate for ID {cert_id}")
                return None
                
            # Parse the certificate
            cert_data = self._parse_certificate_pem(cert_pem, cert_id)
            if cert_data:
                cert_data['id'] = cert_id  # Ensure the ID is set
                return cert_data
            return None
            
        except CRTshError as e:
            logger.error(f"Failed to download certificate ID {cert_id}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error processing certificate ID {cert_id}: {str(e)}", exc_info=True)
            return None
            
    def _der_to_pem(self, der_bytes: bytes) -> str:
        """Convert DER encoded certificate to PEM format."""
        from base64 import b64encode
        b64 = b64encode(der_bytes).decode('ascii')
        chunks = [b64[i:i+64] for i in range(0, len(b64), 64)]
        pem = "-----BEGIN CERTIFICATE-----\n"
        pem += '\n'.join(chunks)
        pem += "\n-----END CERTIFICATE-----"
        return pem
    
    def _parse_certificate_pem(self, cert_pem: str, cert_id: int) -> Optional[Dict[str, Any]]:
        """
        Parse a certificate PEM and extract relevant details efficiently.
        
        Args:
            cert_pem: The PEM-encoded certificate
            cert_id: Certificate ID for error reporting
            
        Returns:
            Dictionary with certificate details or None if parsing fails
        """
        # Import datetime at the function level to ensure it's available
        import datetime as dt
        
        def safe_parse_date(date_str: str) -> Optional[dt.datetime]:
            """Safely parse a date string with multiple formats."""
            if not date_str:
                return None
                
            formats = [
                '%Y-%m-%dT%H:%M:%S',    # ISO format
                '%Y-%m-%d %H:%M:%S',    # SQL format
                '%Y%m%d%H%M%SZ',        # ASN.1 UTC Time
                '%Y%m%d%H%M%S%z',       # ASN.1 GeneralizedTime
                '%Y-%m-%d'              # Just date
            ]
            
            for fmt in formats:
                try:
                    return dt.datetime.strptime(date_str, fmt)
                except (ValueError, TypeError) as e:
                    logger.debug(f"Failed to parse date '{date_str}' with format '{fmt}': {e}")
                    continue
            logger.warning(f"Could not parse date string: {date_str}")
            return None
            
        try:
            # First try with cryptography library which is more reliable
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import hashes
                
                # Clean up the PEM data
                cert_pem = cert_pem.strip()
                if not cert_pem.startswith('-----BEGIN CERTIFICATE-----'):
                    cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_pem}"
                if not cert_pem.endswith('-----END CERTIFICATE-----'):
                    cert_pem = f"{cert_pem}\n-----END CERTIFICATE-----"
                
                try:
                    # Try with default backend first
                    cert = x509.load_pem_x509_certificate(
                        cert_pem.encode('utf-8'),
                        default_backend()
                    )
                except (ValueError, TypeError) as e:
                    # If default backend fails, try with OpenSSL backend as fallback
                    try:
                        from cryptography.hazmat.backends.openssl import backend as openssl_backend
                        cert = x509.load_pem_x509_certificate(
                            cert_pem.encode('utf-8'),
                            openssl_backend
                        )
                    except Exception:
                        # If both backends fail, propagate the original error
                        raise e
                
                # Get basic certificate info with defensive coding
                subject = {}
                try:
                    for attribute in cert.subject:
                        try:
                            key = attribute.oid._name if hasattr(attribute.oid, '_name') else attribute.oid.dotted_string
                            subject[key] = attribute.value
                        except Exception as attr_err:
                            logger.debug(f"Error processing subject attribute: {attr_err}")
                            continue
                except Exception as subj_err:
                    logger.warning(f"Error processing subject: {subj_err}")
                
                issuer = {}
                try:
                    for attribute in cert.issuer:
                        try:
                            key = attribute.oid._name if hasattr(attribute.oid, '_name') else attribute.oid.dotted_string
                            issuer[key] = attribute.value
                        except Exception as attr_err:
                            logger.debug(f"Error processing issuer attribute: {attr_err}")
                            continue
                except Exception as iss_err:
                    logger.warning(f"Error processing issuer: {iss_err}")
                
                # Get public key info with error handling
                key_info = {}
                try:
                    pubkey = cert.public_key()
                    key_info = self._extract_public_key_info(pubkey)
                except Exception as key_err:
                    logger.warning(f"Error extracting public key info: {key_err}")
                    # Fall back to OpenSSL command line
                    key_info = self._extract_public_key_info_openssl(cert_pem)
                    if not key_info:
                        logger.warning("Could not extract public key info with OpenSSL fallback")
                        key_info = {"type": "unknown", "size": 0}
                
                # Get signature algorithm with fallback
                sig_alg = "unknown"
                try:
                    sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
                except Exception as sig_err:
                    logger.warning(f"Error getting signature algorithm: {sig_err}")
                
                # Get validity period with fallbacks
                not_before = ""
                not_after = ""
                days_remaining = 0
                try:
                    not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
                    not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
                    
                    # Calculate days remaining
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)
                    days_remaining = max(0, (cert.not_valid_after - now).days) if cert.not_valid_after > now else 0
                except Exception as date_err:
                    logger.warning(f"Error processing validity dates: {date_err}")
                
                # Get extensions
                extensions = {}
                try:
                    if cert.extensions:
                        for ext in cert.extensions:
                            ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                            try:
                                if ext_name == 'subjectAltName':
                                    extensions[ext_name] = [name.value for name in ext.value]
                                elif ext_name == 'keyUsage':
                                    extensions[ext_name] = [k for k, v in ext.value._key_usage_bit_mapping.items() if v in ext.value]
                                elif ext_name == 'extendedKeyUsage':
                                    extensions[ext_name] = [ku._name for ku in ext.value] if hasattr(ext.value, '__iter__') else str(ext.value)
                                else:
                                    extensions[ext_name] = str(ext.value)
                            except Exception as ext_error:
                                logger.debug(f"Error processing extension {ext_name}: {str(ext_error)}")
                                extensions[ext_name] = 'error_processing_extension'
                except Exception as ext_error:
                    logger.warning(f"Error reading certificate extensions: {str(ext_error)}")
                
                # Build the result dictionary
                result = {
                    'id': cert_id,
                    'subject': subject,
                    'issuer': issuer,
                    'version': f"X.509v{cert.version.value}",
                    'serial_number': str(cert.serial_number),
                    'public_key': key_info,
                    'signature_algorithm': sig_alg,
                    'validity': {
                        'not_before': not_before,
                        'not_after': not_after,
                        'days_remaining': days_remaining
                    },
                    'extensions': extensions if extensions else {}
                }
                
                # Add fingerprints if available
                try:
                    result['fingerprints'] = {
                        'sha1': cert.fingerprint(hashes.SHA1()).hex(),
                        'sha256': cert.fingerprint(hashes.SHA256()).hex()
                    }
                except Exception as fp_error:
                    logger.debug(f"Error calculating certificate fingerprints: {str(fp_error)}")
                
                return result
                
            except ImportError:
                logger.debug("cryptography library not available, falling back to OpenSSL")
                return self._parse_with_openssl(cert_pem, cert_id)
                
        except Exception as e:
            logger.error(f"Error parsing certificate {cert_id}: {str(e)}")
            logger.debug("Error details:", exc_info=True)
            return None
            
    def _extract_public_key_info_openssl(self, cert_pem: str) -> Dict[str, Any]:
        """Extract public key information using OpenSSL command line."""
        import subprocess
        import tempfile
        import os
        
        try:
            # Write the certificate to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                tmp.write(cert_pem)
                tmp_path = tmp.name
                
            try:
                # Run OpenSSL to get public key info
                result = subprocess.run(
                    ['openssl', 'x509', '-in', tmp_path, '-noout', '-text'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode != 0:
                    logger.warning(f"OpenSSL command failed: {result.stderr}")
                    return {}
                
                output = result.stdout
                key_info = {}
                
                # Parse the output to get key info
                if 'Public Key Algorithm:' in output:
                    algo_line = [line for line in output.split('\n') 
                               if 'Public Key Algorithm:' in line][0]
                    if 'rsa' in algo_line.lower():
                        key_info['type'] = 'rsa'
                        # Extract RSA key size
                        if 'RSA Public-Key: (' in output:
                            size_line = [line for line in output.split('\n') 
                                       if 'RSA Public-Key: (' in line][0]
                            key_info['size'] = int(size_line.split('(')[1].split()[0])
                    elif 'ec' in algo_line.lower():
                        key_info['type'] = 'ec'
                        # Extract curve name if available
                        if 'NIST CURVE:' in output:
                            curve_line = [line for line in output.split('\n') 
                                        if 'NIST CURVE:' in line][0]
                            key_info['curve'] = curve_line.split(':')[1].strip()
                    elif 'ed25519' in algo_line.lower():
                        key_info['type'] = 'ed25519'
                    elif 'ed448' in algo_line.lower():
                        key_info['type'] = 'ed448'
                        
                return key_info
                
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                    
        except Exception as e:
            logger.warning(f"Error in OpenSSL fallback: {e}")
            return {}
            
    def _extract_public_key_info(self, pubkey) -> Dict[str, Any]:
        """Extract public key information from a cryptography public key object."""
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
        
        key_info = {'type': 'Unknown', 'bits': None, 'details': {}}
        
        try:
            if isinstance(pubkey, rsa.RSAPublicKey):
                nums = pubkey.public_numbers()
                key_info.update({
                    'type': 'RSA',
                    'bits': pubkey.key_size,
                    'details': {
                        'modulus': nums.n,
                        'public_exponent': nums.e
                    }
                })
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                nums = pubkey.public_numbers()
                key_info.update({
                    'type': 'EC',
                    'bits': pubkey.key_size,
                    'details': {
                        'curve': pubkey.curve.name if hasattr(pubkey.curve, 'name') else str(pubkey.curve),
                        'x': nums.x,
                        'y': nums.y
                    }
                })
            elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                is_ed25519 = isinstance(pubkey, ed25519.Ed25519PublicKey)
                key_info.update({
                    'type': 'EdDSA',
                    'bits': 255 if is_ed25519 else 448,
                    'details': {
                        'algorithm': 'Ed25519' if is_ed25519 else 'Ed448'
                    }
                })
            elif isinstance(pubkey, dsa.DSAPublicKey):
                key_info.update({
                    'type': 'DSA',
                    'bits': pubkey.key_size,
                    'details': {}
                })
        except Exception as e:
            logger.warning(f"Error extracting public key details: {str(e)}")
            
        return key_info
        
    def _parse_with_openssl(self, cert_pem: str, cert_id: int) -> Optional[Dict[str, Any]]:
        """Fallback method to parse certificate using OpenSSL."""
        try:
            import OpenSSL.crypto
            import ssl
            from datetime import datetime
            
            # Load the certificate
            try:
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert_pem.encode('utf-8')
                )
            except Exception as e:
                if "X509_V_FLAG_NOTIFY_POLICY" in str(e):
                    # Workaround for older OpenSSL versions
                    cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert_der
                    )
                else:
                    raise
            
            # Extract basic information
            subject = {}
            for component in cert.get_subject().get_components():
                try:
                    key = component[0].decode('utf-8')
                    value = component[1].decode('utf-8')
                    subject[key] = value
                except Exception:
                    continue
            
            issuer = {}
            for component in cert.get_issuer().get_components():
                try:
                    key = component[0].decode('utf-8')
                    value = component[1].decode('utf-8')
                    issuer[key] = value
                except Exception:
                    continue
            
            # Get public key info
            pubkey = cert.get_pubkey()
            key_type = (
                'RSA' if pubkey.type() == OpenSSL.crypto.TYPE_RSA
                else 'EC' if pubkey.type() == OpenSSL.crypto.TYPE_EC
                else 'Unknown'
            )
            
            # Build the result
            result = {
                'id': cert_id,
                'subject': subject,
                'issuer': issuer,
                'version': f"X.509v{cert.get_version() + 1}",
                'serial_number': str(cert.get_serial_number()),
                'public_key': {
                    'type': key_type,
                    'bits': pubkey.bits(),
                    'details': {}
                },
                'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
                'validity': {
                    'not_before': datetime.strptime(
                        cert.get_notBefore().decode('utf-8'),
                        '%Y%m%d%H%M%SZ'
                    ).isoformat(),
                    'not_after': datetime.strptime(
                        cert.get_notAfter().decode('utf-8'),
                        '%Y%m%d%H%M%SZ'
                    ).isoformat()
                }
            }
            
            return result
            
        except Exception as e:
            logger.error(f"OpenSSL fallback failed for certificate {cert_id}: {str(e)}")
            return None
            
        # Fall back to OpenSSL if cryptography is not available
        try:
            import OpenSSL.crypto
            
            # Clean up the PEM data if needed
            cert_pem = cert_pem.strip()
            if not cert_pem.startswith('-----BEGIN CERTIFICATE-----'):
                cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_pem}"
            if not cert_pem.endswith('-----END CERTIFICATE-----'):
                cert_pem = f"{cert_pem}\n-----END CERTIFICATE-----"
                
            # Load the certificate with error handling for OpenSSL version issues
            try:
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    cert_pem.encode()
                )
            except Exception as e:
                if "X509_V_FLAG_NOTIFY_POLICY" in str(e):
                    # Workaround for older OpenSSL versions
                    import ssl
                    cert = ssl.PEM_cert_to_DER_cert(cert_pem)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert
                    )
                else:
                    raise
            
            # Get public key information
            pubkey = cert.get_pubkey()
            key_type = (
                'RSA' if pubkey.type() == OpenSSL.crypto.TYPE_RSA
                else 'EC' if pubkey.type() == OpenSSL.crypto.TYPE_EC
                else 'Unknown'
            )
            key_bits = pubkey.bits()
            
            # Get signature algorithm
            sig_alg = cert.get_signature_algorithm().decode()
            
            # Get subject and issuer
            def parse_name(name):
                result = {}
                for component in name.get_components():
                    try:
                        key = component[0].decode()
                        value = component[1].decode()
                        result[key] = value
                    except Exception:
                        continue
                return result
            
            subject = parse_name(cert.get_subject())
            issuer = parse_name(cert.get_issuer())
            
            # Get validity dates
            not_before = cert.get_notBefore().decode()
            not_after = cert.get_notAfter().decode()
            
            # Get version
            version = cert.get_version() + 1  # X509v1 is 0, X509v3 is 2, etc.
            
            return {
                'public_key': {
                    'type': key_type,
                    'bits': key_bits,
                    'algorithm': f"{key_type}{key_bits}" if key_type != 'EC' else key_type
                },
                'signature_algorithm': {
                    'name': sig_alg.split('With')[0] if 'With' in sig_alg else sig_alg,
                    'full_name': sig_alg
                },
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'version': f"X.509v{version}",
                'serial_number': str(cert.get_serial_number())
            }
            
        except Exception as cert_error:
            logger.error(f"Error parsing certificate with ID {cert_id}: {str(cert_error)}")
            # Save the problematic certificate for debugging
            with open(f'problematic_cert_{cert_id}.pem', 'w') as f:
                f.write(cert_pem)
            logger.debug(f"Saved problematic certificate to problematic_cert_{cert_id}.pem")
            return None
    
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        """
        Make an HTTP request with retry logic and error handling.
        
        Args:
            url: The URL to request
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            The response object
            
        Raises:
            CRTshConnectionError: If there's a connection error after all retries
            CRTshRateLimitError: If rate limited by the server
            CRTshError: For other request errors
        """
        # Set default timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
            
        # Set verify_ssl if not specified
        if 'verify' not in kwargs:
            kwargs['verify'] = self.verify_ssl
            
        attempt = 0
        last_exception = None
        
        while attempt <= self.max_retries:
            try:
                response = self.session.request(method, url, **kwargs)
                
                # Check for rate limiting (429 Too Many Requests)
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 5))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds before retry...")
                    time.sleep(retry_after)
                    attempt += 1
                    continue
                    
                # For 4xx errors (except 429), don't retry
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    if response.status_code == 404:
                        raise CRTshNotFoundError(f"Certificate not found: {url}")
                    response.raise_for_status()
                    
                # For 5xx errors, let the retry logic handle it
                response.raise_for_status()
                
                return response
                
            except requests.exceptions.SSLError as e:
                logger.error(f"SSL error connecting to {url}: {str(e)}")
                raise CRTshConnectionError(f"SSL error: {str(e)}")
                
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                attempt_info = f"attempt {attempt + 1}/{self.max_retries}"
                logger.warning(f"Connection error ({attempt_info}): {str(e)}")
                
            except requests.exceptions.Timeout as e:
                last_exception = e
                attempt_info = f"attempt {attempt + 1}/{self.max_retries}"
                logger.warning(f"Timeout error ({attempt_info}): {str(e)}")
                
            except requests.exceptions.RequestException as e:
                last_exception = e
                attempt_info = f"attempt {attempt + 1}/{self.max_retries}"
                logger.error(f"Request failed ({attempt_info}): {str(e)}")
                
            # Calculate backoff time
            if attempt < self.max_retries:
                backoff_time = self.backoff_factor * (2 ** attempt)
                logger.debug(f"Retrying in {backoff_time:.2f} seconds...")
                time.sleep(backoff_time)
                
            attempt += 1
        
        # If we get here, all retries failed
        raise CRTshConnectionError(f"Failed after {self.max_retries} attempts: {str(last_exception)}")
    
    def _download_single_certificate(self, cert_id: int) -> Tuple[int, Optional[Dict[str, Any]]]:
        """
        Download a single certificate with proper error handling.
        
        Args:
            cert_id: The certificate ID to download
            
        Returns:
            Tuple of (certificate_id, certificate_data) where certificate_data is None if download failed
        """
        try:
            self._rate_limit()
            cert_data = self._get_certificate_download(cert_id)
            if cert_data:
                logger.info(f"Downloaded certificate {cert_id}")
                return cert_id, cert_data
            return cert_id, None
        except Exception as e:
            logger.warning(f"Error downloading certificate {cert_id}: {str(e)}")
            return cert_id, None

    def get_certificates_concurrently(self, cert_ids: 'List[int]', max_workers: int = 10, max_retries: int = 3) -> 'Dict[int, Dict[str, Any]]':
        """
        Download multiple certificates concurrently with retry logic.
        
        Args:
            cert_ids: List of certificate IDs to download
            max_workers: Maximum number of concurrent downloads (default: 10)
            max_retries: Maximum number of retry attempts for failed downloads (default: 3)
            
        Returns:
            Dictionary mapping certificate IDs to their details
        """
        import time
        
        results: Dict[int, Dict[str, Any]] = {}
        failed_cert_ids = set()
        remaining_attempts = max_retries
        
        while remaining_attempts > 0 and cert_ids:
            logger.info(f"Starting download of {len(cert_ids)} certificates (attempt {max_retries - remaining_attempts + 1}/{max_retries})")
            attempt_results = {}
            
            with ThreadPoolExecutor(max_workers=min(max_workers, len(cert_ids))) as executor:
                # Submit all certificate downloads for this attempt
                future_to_cert = {
                    executor.submit(self._download_single_certificate, cert_id): cert_id 
                    for cert_id in cert_ids
                }
                
                # Process completed downloads
                for future in as_completed(future_to_cert):
                    cert_id = future_to_cert[future]
                    try:
                        cert_id, cert_data = future.result()
                        if cert_data:
                            results[cert_id] = cert_data
                            attempt_results[cert_id] = True
                        else:
                            failed_cert_ids.add(cert_id)
                            attempt_results[cert_id] = False
                    except Exception as e:
                        logger.warning(f"Error downloading certificate {cert_id}: {str(e)}")
                        failed_cert_ids.add(cert_id)
                        attempt_results[cert_id] = False
            
            # Log attempt results
            success_count = sum(1 for success in attempt_results.values() if success)
            failure_count = len(attempt_results) - success_count
            logger.info(f"Download attempt completed: {success_count} succeeded, {failure_count} failed")
            
            # Prepare for next attempt if needed
            remaining_attempts -= 1
            if remaining_attempts > 0 and failed_cert_ids:
                cert_ids = list(failed_cert_ids)
                failed_cert_ids = set()
                if cert_ids:
                    logger.info(f"Retrying {len(cert_ids)} failed downloads...")
                    # Add a small delay between retries to avoid overwhelming the server
                    time.sleep(2)
            else:
                break
                
        if failed_cert_ids:
            logger.warning(f"Failed to download {len(failed_cert_ids)} certificates after {max_retries} attempts")
            
        return results           

    def _get_certificate_details(self, cert_id: int) -> 'Optional[Dict[str, Any]]':
        """
        Fetch full certificate details from crt.sh by ID using direct download.
        
        Args:
            cert_id: The certificate ID to look up
            
        Returns:
            Dictionary with certificate details or None if not found
        """
        logger.debug(f"Fetching certificate {cert_id} using direct download")
        try:
            # Apply rate limiting before request
            self._rate_limit()
            cert_data = self._get_certificate_download(cert_id)
            if cert_data:
                logger.info(f"Successfully downloaded certificate {cert_id}")
            return cert_data
        except Exception as e:
            logger.error(f"Error fetching certificate details for ID {cert_id}: {str(e)}")
            logger.debug("Error details:", exc_info=True)
            return None
    
    def _safe_parse_asn1(self, data: Any, cert_id: str, field_name: str) -> Any:
        """Safely parse ASN.1 data with detailed error handling."""
        logger = logging.getLogger('pqctlog.crtsh')
        
        if data is None:
            logger.debug(f"[CERT {cert_id}] No data provided for {field_name}")
            return None
            
        try:
            # Try to get a string representation for debugging
            str_repr = str(data)[:100] + ('...' if len(str(data)) > 100 else '')
            logger.debug(f"[CERT {cert_id}] Parsing {field_name} (type: {type(data).__name__}, value: {str_repr})")
            
            # If it's already a string, try to parse it
            if isinstance(data, str):
                return data
                
            # If it's bytes, try to decode it
            if isinstance(data, bytes):
                try:
                    # Try UTF-8 first
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        # Fall back to hex representation if not valid UTF-8
                        return data.hex()
                    except Exception as e:
                        logger.warning(f"[CERT {cert_id}] Failed to decode bytes for {field_name}: {str(e)}")
                        return None
                        
            # For other types, try to convert to string
            try:
                return str(data)
            except Exception as e:
                logger.warning(f"[CERT {cert_id}] Failed to convert {field_name} to string: {str(e)}")
                return None
                
        except Exception as e:
            logger.error(f"[CERT {cert_id}] Error in _safe_parse_asn1 for {field_name}: {str(e)}")
            logger.debug(f"[CERT {cert_id}] Error details:", exc_info=True)
            return None

    def _process_certificate(self, cert_data: 'Dict[str, Any]') -> 'Optional[Dict[str, Any]]':
        """Process and normalize certificate data from crt.sh.
        
        Args:
            cert_data: Raw certificate data from crt.sh
            
        Returns:
            Processed certificate data with all required fields, or None if processing fails
        """
        logger = logging.getLogger('pqctlog.crtsh')
        
        # Log the raw certificate data for debugging
        logger.debug("Raw certificate data received:")
        for key, value in cert_data.items():
            if key in ['raw', 'certificate', 'cert']:  # Skip potentially large binary data
                logger.debug(f"  {key}: <{type(value).__name__} length={len(value) if hasattr(value, '__len__') else 'N/A'}>")
            else:
                logger.debug(f"  {key}: {value!r} <{type(value).__name__}>")
                
        # Check for known problematic fields
        asn1_suspects = ['tbs_noct_feedback', 'tbs_fingerprint', 'sha1_fingerprint', 'sha256_fingerprint', 'spki_subject_fingerprint']
        for suspect in asn1_suspects:
            if suspect in cert_data:
                val = cert_data[suspect]
                logger.debug(f"ASN.1 suspect field '{suspect}': {val!r} <{type(val).__name__}>")
        
        try:
            # Extract certificate ID early for error reporting
            cert_id = str(cert_data.get('id', 'unknown'))
            logger.debug(f"[CERT {cert_id}] Starting certificate processing")
            
            # Check for required fields
            required_fields = ['id', 'issuer_name', 'not_before', 'not_after']
            missing_fields = [f for f in required_fields if f not in cert_data]
            if missing_fields:
                logger.warning(f"[CERT {cert_id}] Missing required fields: {', '.join(missing_fields)}")
                
            # Log the raw values of important fields
            important_fields = ['issuer_name', 'not_before', 'not_after', 'serial_number', 'name_value']
            for field in important_fields:
                if field in cert_data:
                    val = cert_data[field]
                    logger.debug(f"[CERT {cert_id}] {field}: {val!r} <{type(val).__name__}>")
            
            if not cert_id:
                logger.error("Certificate data is missing required 'id' field")
                return None
                
            # Enhanced debug logging for certificate data
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    # Log the raw data types and values
                    logger.debug(f"[CERT {cert_id}] Certificate data structure:")
                    for key, value in cert_data.items():
                        if key in ['raw', 'certificate', 'cert']:  # Skip potentially large binary data
                            logger.debug(f"[CERT {cert_id}]   {key}: <{type(value).__name__} length={len(value) if hasattr(value, '__len__') else 'N/A'}>")
                        else:
                            logger.debug(f"[CERT {cert_id}]   {key}: {value!r} <{type(value).__name__}>")
                    
                    # Log the raw values of important fields with types
                    important_fields = [
                        'common_name', 'issuer_name', 'name_value', 'not_before', 'not_after',
                        'serial_number', 'sha1', 'sha256', 'spki_subject_fingerprint'
                    ]
                    for field in important_fields:
                        if field in cert_data:
                            val = cert_data[field]
                            logger.debug(f"[CERT {cert_id}] {field}: {val!r} <{type(val).__name__}>")
                    
                    # Log a sample of the raw data (excluding large binary fields)
                    sample_data = {k: v for k, v in cert_data.items() 
                                 if not isinstance(v, (bytes, bytearray)) and 
                                 not (isinstance(v, str) and len(v) > 100)}
                    logger.debug(f"[CERT {cert_id}] Sample data (excluding large fields): {sample_data}")
                    
                except Exception as e:
                    logger.error(f"[CERT {cert_id}] Error during debug logging: {str(e)}", exc_info=True)
            
            # Extract common fields with defaults
            common_name = cert_data.get('common_name', '')
            issuer_dn = cert_data.get('issuer_name', '')
            subject_dn = cert_data.get('name_value', common_name)  # Fallback to common_name if name_value not available
            
            logger.debug(f"[CERT {cert_id}] Extracted basic fields:")
            logger.debug(f"[CERT {cert_id}]   common_name: {common_name!r}")
            logger.debug(f"[CERT {cert_id}]   issuer_dn: {issuer_dn!r}")
            logger.debug(f"[CERT {cert_id}]   subject_dn: {subject_dn!r}")
            
            # Safely parse dates with error handling
            not_before = None
            not_after = None
            
            # Safely get raw values with fallbacks
            not_before_raw = cert_data.get('not_before')
            not_after_raw = cert_data.get('not_after')
            
            # Log raw values with type information
            logger.debug(f"[CERT {cert_id}] Raw date values:")
            logger.debug(f"[CERT {cert_id}]   not_before: {not_before_raw!r} (type: {type(not_before_raw).__name__})")
            logger.debug(f"[CERT {cert_id}]   not_after: {not_after_raw!r} (type: {type(not_after_raw).__name__})")
            
            # Parse not_before with enhanced error handling
            try:
                if not_before_raw is not None:
                    not_before = self._parse_date(not_before_raw)
                    logger.debug(f"[CERT {cert_id}] Parsed not_before: {not_before}")
                else:
                    logger.debug(f"[CERT {cert_id}] No not_before date provided")
            except Exception as e:
                logger.warning(f"[CERT {cert_id}] Failed to parse not_before date: {str(e)}")
                logger.debug(f"[CERT {cert_id}] not_before raw value: {not_before_raw!r}", exc_info=True)
                not_before = None
                
                # Try to extract date from raw value as string
                try:
                    if not_before_raw is not None:
                        str_val = str(not_before_raw)
                        logger.debug(f"[CERT {cert_id}] Attempting fallback parsing of not_before as string: {str_val}")
                        # Try to extract YYYY-MM-DD pattern
                        import re
                        match = re.search(r'(\d{4}-\d{2}-\d{2})', str_val)
                        if match:
                            not_before = datetime.strptime(match.group(1), '%Y-%m-%d')
                            logger.debug(f"[CERT {cert_id}] Successfully extracted date from not_before string: {not_before}")
                except Exception as fallback_e:
                    logger.debug(f"[CERT {cert_id}] Fallback parsing failed: {str(fallback_e)}")
            
            # Parse not_after with enhanced error handling
            try:
                if not_after_raw is not None:
                    not_after = self._parse_date(not_after_raw)
                    logger.debug(f"[CERT {cert_id}] Parsed not_after: {not_after}")
                else:
                    logger.debug(f"[CERT {cert_id}] No not_after date provided")
            except Exception as e:
                logger.warning(f"[CERT {cert_id}] Failed to parse not_after date: {str(e)}")
                logger.debug(f"[CERT {cert_id}] not_after raw value: {not_after_raw!r}", exc_info=True)
                not_after = None
                
                # Try to extract date from raw value as string
                try:
                    if not_after_raw is not None:
                        str_val = str(not_after_raw)
                        logger.debug(f"[CERT {cert_id}] Attempting fallback parsing of not_after as string: {str_val}")
                        # Try to extract YYYY-MM-DD pattern
                        import re
                        match = re.search(r'(\d{4}-\d{2}-\d{2})', str_val)
                        if match:
                            not_after = datetime.strptime(match.group(1), '%Y-%m-%d')
                            logger.debug(f"[CERT {cert_id}] Successfully extracted date from not_after string: {not_after}")
                except Exception as fallback_e:
                    logger.debug(f"[CERT {cert_id}] Fallback parsing failed: {str(fallback_e)}")
            
            # Log final date values
            logger.debug(f"[CERT {cert_id}] Final date values - not_before: {not_before}, not_after: {not_after}")
            
            # Parse names (can be newline-separated)
            names = []
            if 'name_value' in cert_data and cert_data['name_value']:
                logger.debug(f"[CERT {cert_id}] Parsing name_value: {cert_data['name_value']!r}")
                try:
                    names = [name.strip() for name in cert_data['name_value'].split('\n') if name.strip()]
                    logger.debug(f"[CERT {cert_id}] Extracted names: {names}")
                except Exception as e:
                    logger.warning(f"[CERT {cert_id}] Failed to parse name_value: {str(e)}")
                    logger.debug(f"[CERT {cert_id}] name_value raw value: {cert_data['name_value']!r}", exc_info=True)
                    names = []
            else:
                logger.debug(f"[CERT {cert_id}] No name_value field or empty value")
            
            # Skip downloading additional certificate details
            cert_details = None
            logger.debug(f"[CERT {cert_id}] Skipping certificate details download")
            
            # Log raw certificate data for debugging ASN.1 issues
            try:
                logger.debug(f"[CERT {cert_id}] Raw certificate data types and values:")
                for key, value in cert_data.items():
                    if key in ['raw', 'certificate', 'cert']:  # Skip potentially large binary data
                        logger.debug(f"[CERT {cert_id}]   {key}: <{type(value).__name__} length={len(value) if hasattr(value, '__len__') else 'N/A'}>")
                    else:
                        logger.debug(f"[CERT {cert_id}]   {key}: {value!r} <{type(value).__name__}>")
                
                # Log the exact data that might be causing ASN.1 parsing issues
                asn1_suspects = ['tbs_noct_feedback', 'tbs_fingerprint', 'sha1_fingerprint', 'sha256_fingerprint', 'spki_subject_fingerprint']
                for suspect in asn1_suspects:
                    if suspect in cert_data:
                        val = cert_data[suspect]
                        logger.debug(f"[CERT {cert_id}] ASN.1 suspect field '{suspect}': {val!r} <{type(val).__name__}>")
                        
            except Exception as e:
                logger.debug(f"[CERT {cert_id}] Error during debug logging: {str(e)}", exc_info=True)
            
            # Initialize subject and issuer with all required fields and empty defaults
            required_fields = [
                'commonName', 'organizationName', 'organizationalUnitName',
                'countryName', 'localityName', 'stateOrProvinceName', 'emailAddress'
            ]
            subject = {field: '' for field in required_fields}
            if common_name:
                subject['commonName'] = common_name
                
            issuer = {field: '' for field in required_fields}
            if issuer_dn:
                # Simple extraction of CN from DN
                for part in issuer_dn.split(','):
                    part = part.strip()
                    if part.startswith('CN='):
                        issuer['commonName'] = part[3:]
                    elif part.startswith('O='):
                        issuer['organizationName'] = part[2:]
                    elif part.startswith('C='):
                        issuer['countryName'] = part[2:]
                    elif part.startswith('L='):
                        issuer['localityName'] = part[2:]
                    elif part.startswith('ST='):
                        issuer['stateOrProvinceName'] = part[3:]
                    elif part.startswith('OU='):
                        issuer['organizationalUnitName'] = part[3:]
                    elif part.startswith('emailAddress='):
                        issuer['emailAddress'] = part[13:]
            
            # Define parse_dn function for DN parsing
            def parse_dn(dn):
                if not dn:
                    logger.debug(f"[CERT {cert_id}] parse_dn: Empty DN provided")
                    return {}
                    
                logger.debug(f"[CERT {cert_id}] parse_dn: Parsing DN: {dn!r}")
                parts = {}
                
                try:
                    for part in dn.split(','):
                        part = part.strip()
                        logger.debug(f"[CERT {cert_id}] parse_dn: Processing part: {part!r}")
                        if '=' in part:
                            key, value = part.split('=', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            logger.debug(f"[CERT {cert_id}] parse_dn: Key: {key!r}, Value: {value!r}")
                            
                            if key == 'cn':
                                parts['commonName'] = value
                            elif key == 'o':
                                parts['organizationName'] = value
                            elif key == 'ou':
                                parts['organizationalUnitName'] = value
                            elif key == 'c':
                                parts['countryName'] = value
                            elif key == 'l':
                                parts['localityName'] = value
                            elif key == 'st':
                                parts['stateOrProvinceName'] = value
                            elif key == 'emailaddress':
                                parts['emailAddress'] = value
                            else:
                                logger.debug(f"[CERT {cert_id}] parse_dn: Unknown key: {key!r}")
                    
                    logger.debug(f"[CERT {cert_id}] parse_dn: Parsed parts: {parts}")
                    return parts if parts else {'commonName': dn}
                    
                except Exception as e:
                    logger.error(f"[CERT {cert_id}] Error parsing DN '{dn}': {str(e)}")
                    logger.debug(f"[CERT {cert_id}] DN parsing error details:", exc_info=True)
                    return {'commonName': dn}
            
            # Initialize subject_dn from common_name if not set
            subject_dn = cert_data.get('common_name', '')
            logger.debug(f"[CERT {cert_id}] Initial subject_dn: {subject_dn!r}")
            
            # Parse subject and issuer DNs if available
            if subject_dn and subject_dn != 'None':
                logger.debug(f"[CERT {cert_id}] Parsing subject DN: {subject_dn!r}")
                try:
                    parsed_subject = parse_dn(subject_dn)
                    logger.debug(f"[CERT {cert_id}] Parsed subject: {parsed_subject}")
                    
                    # Only update non-empty values
                    updates = {k: v for k, v in parsed_subject.items() if v and v != 'None'}
                    logger.debug(f"[CERT {cert_id}] Updating subject with: {updates}")
                    
                    subject.update(updates)
                    logger.debug(f"[CERT {cert_id}] Updated subject: {subject}")
                    
                except Exception as e:
                    logger.warning(f"[CERT {cert_id}] Error parsing subject DN: {str(e)}")
                    logger.debug(f"[CERT {cert_id}] Subject DN parsing error details:", exc_info=True)
            else:
                logger.debug(f"[CERT {cert_id}] No subject DN to parse")
            
            if issuer_dn and issuer_dn != 'None':
                logger.debug(f"[CERT {cert_id}] Parsing issuer DN: {issuer_dn!r}")
                try:
                    parsed_issuer = parse_dn(issuer_dn)
                    logger.debug(f"[CERT {cert_id}] Parsed issuer: {parsed_issuer}")
                    
                    # Only update non-empty values
                    updates = {k: v for k, v in parsed_issuer.items() if v and v != 'None'}
                    logger.debug(f"[CERT {cert_id}] Updating issuer with: {updates}")
                    
                    issuer.update(updates)
                    logger.debug(f"[CERT {cert_id}] Updated issuer: {issuer}")
                    
                except Exception as e:
                    logger.warning(f"[CERT {cert_id}] Error parsing issuer DN: {str(e)}")
                    logger.debug(f"[CERT {cert_id}] Issuer DN parsing error details:", exc_info=True)
            else:
                logger.debug(f"[CERT {cert_id}] No issuer DN to parse")
            
            # Ensure we have at least a commonName
            if not subject.get('commonName') and common_name:
                subject['commonName'] = common_name
            elif not subject.get('commonName'):
                subject['commonName'] = subject_dn if subject_dn and subject_dn != 'None' else 'Unknown'
                
            if not issuer.get('commonName') and issuer_dn:
                issuer['commonName'] = issuer_dn.split(',')[0].split('=')[-1] if '=' in issuer_dn else issuer_dn
            elif not issuer.get('commonName'):
                issuer['commonName'] = 'Unknown'
            
            # Build the result dictionary with all required fields and proper defaults
            try:
                # Log the state before building the result
                logger.debug(f"[CERT {cert_id}] Building result dictionary")
                logger.debug(f"[CERT {cert_id}] Subject state: {subject}")
                logger.debug(f"[CERT {cert_id}] Issuer state: {issuer}")
                
                # Ensure we have valid subject and issuer dictionaries
                if not isinstance(subject, dict):
                    logger.warning(f"[CERT {cert_id}] Invalid subject type: {type(subject).__name__}, converting to empty dict")
                    subject = {}
                if not isinstance(issuer, dict):
                    logger.warning(f"[CERT {cert_id}] Invalid issuer type: {type(issuer).__name__}, converting to empty dict")
                    issuer = {}

                # Build the result dictionary with all required fields and proper defaults
                result = {
                    'id': str(cert_id) if cert_id is not None else '',
                    'serial_number': str(cert_data.get('serial_number', cert_id)) if cert_data.get('serial_number') or cert_id else '',
                    'sha256_fingerprint': str(cert_data.get('sha256', '')),
                    'subject': subject,
                    'issuer': issuer,
                    'subject_dn': subject_dn if isinstance(subject_dn, str) else '',
                    'issuer_dn': issuer_dn if isinstance(issuer_dn, str) else '',
                    'validity': {
                        'not_before': not_before.isoformat() if not_before else '',
                        'not_after': not_after.isoformat() if not_after else '',
                        'is_valid': not_after > datetime.utcnow() if not_after else False
                    },
                    'key_algorithm': str(cert_data.get('key_algorithm', '')),
                    'key_size': int(cert_data.get('key_size', 0)) if str(cert_data.get('key_size', '')).isdigit() else 0,
                    'key_type': str(cert_data.get('key_type', '')),
                    'signature_algorithm': {
                        'name': str(cert_data.get('signature_algorithm', '')),
                        'is_quantum_vulnerable': False,
                        'is_post_quantum': False,
                        'pq_algorithm_type': None,
                        'security_level': None
                    },
                    'extensions': cert_data.get('extensions', {}) if isinstance(cert_data.get('extensions'), dict) else {},
                    'is_ca': bool(cert_data.get('is_ca', False)),
                    'version': int(cert_data.get('version', 3)) if str(cert_data.get('version', '3')).isdigit() else 3,
                    'san': names if isinstance(names, list) else [],
                    'raw': cert_data.get('raw', {}) if isinstance(cert_data.get('raw'), dict) else {},
                    'processed_at': datetime.utcnow().isoformat()
                }
                
            except Exception as e:
                logger.error(f"Error building result dictionary: {str(e)}")
                # Return a minimal valid result with just the ID and error information
                return {
                    'id': str(cert_id) if cert_id is not None else 'unknown',
                    'error': f"Failed to process certificate: {str(e)}",
                    'raw_data_available': bool(cert_data)
                }

            # Add public key and signature algorithm from cert_details if available
            try:
                if cert_details:
                    logger.debug(f"[CERT {cert_id}] Processing cert_details")
                    if 'public_key' in cert_details and cert_details['public_key']:
                        logger.debug(f"[CERT {cert_id}] Adding public key")
                        result['public_key'] = cert_details['public_key']
                    if 'signature_algorithm' in cert_details and cert_details['signature_algorithm']:
                        logger.debug(f"[CERT {cert_id}] Updating signature algorithm")
                        result['signature_algorithm'].update({
                            k: v for k, v in cert_details['signature_algorithm'].items() 
                            if v is not None and k in result['signature_algorithm']
                        })
            except Exception as e:
                logger.error(f"[CERT {cert_id}] Error processing cert_details: {str(e)}")
                logger.debug(f"[CERT {cert_id}] cert_details: {cert_details}", exc_info=True)
            
            # Debug log the final certificate structure
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"[CERT {cert_id}] Final certificate structure:")
                logger.debug(f"[CERT {cert_id}] Subject: {result.get('subject', 'N/A')}")
                logger.debug(f"[CERT {cert_id}] Issuer: {result.get('issuer', 'N/A')}")
                logger.debug(f"[CERT {cert_id}] Validity: {result.get('validity', 'N/A')}")
                logger.debug(f"[CERT {cert_id}] Signature Algorithm: {result.get('signature_algorithm', 'N/A')}")
                
                # Log a sample of the result to avoid huge logs
                sample_result = {k: v for k, v in result.items() if k not in ['raw', 'extensions']}
                if 'extensions' in result:
                    sample_result['extensions'] = f"<dict with {len(result['extensions'])} items>"
                if 'raw' in result:
                    sample_result['raw'] = f"<raw data {len(result['raw'])} bytes>"
                
                logger.debug(f"[CERT {cert_id}] Result sample: {sample_result}")
                
            return result
            
        except Exception as e:
            logger.error(f"Error processing certificate {cert_id}: {str(e)}")
            logger.debug("Certificate data that caused the error:", exc_info=True)
            if logger.isEnabledFor(logging.DEBUG):
                import json
                logger.debug(json.dumps(cert_data, indent=2, default=str, ensure_ascii=False))
            return None

    def _parse_date(self, date_str: 'Optional[str]') -> 'Optional[datetime]':
        """Parse a date string from crt.sh into a datetime object.
        
        Handles multiple date formats including:
        - ISO format: '2023-01-01T00:00:00'
        - ASN.1 UTC Time: '230101000000Z' (YYMMDDhhmmssZ)
        - ASN.1 GeneralizedTime: '20230101000000Z' (YYYYMMDDhhmmssZ)
        
        Args:
            date_str: Date string in various formats
                
        Returns:
            datetime object or None if parsing fails
        """
        logger = logging.getLogger('pqctlog.crtsh')
        
        if not date_str:
            logger.debug("No date string provided to _parse_date")
            return None
            
        # If it's already a datetime object, return it
        if isinstance(date_str, datetime):
            logger.debug(f"Date is already a datetime: {date_str}")
            return date_str
            
        # If it's a timestamp (float or int)
        if isinstance(date_str, (int, float)):
            try:
                result = datetime.fromtimestamp(float(date_str))
                logger.debug(f"Parsed timestamp {date_str} as {result}")
                return result
            except (ValueError, TypeError) as e:
                logger.debug(f"Failed to parse timestamp {date_str}: {str(e)}")
                pass
                
        # Remove any extra whitespace and convert to string
        try:
            date_str = str(date_str).strip()
            logger.debug(f"Processing date string: {date_str}")
        except Exception as e:
            logger.error(f"Failed to convert date_str to string: {str(e)}")
            logger.debug(f"date_str type: {type(date_str)}, value: {date_str!r}")
            return None
        
        # Try different date formats
        formats = [
            ('%Y-%m-%dT%H:%M:%S', 'ISO format'),  # ISO format
            ('%Y%m%d%H%M%SZ', 'ASN.1 GeneralizedTime'),  # ASN.1 GeneralizedTime
            ('%y%m%d%H%M%SZ', 'ASN.1 UTC Time'),  # ASN.1 UTC Time
            ('%Y-%m-%d %H:%M:%S', 'SQL format'),  # SQL format
            ('%Y-%m-%d', 'Date only'),  # Just date
        ]
        
        for fmt, fmt_name in formats:
            try:
                result = datetime.strptime(date_str, fmt)
                logger.debug(f"Successfully parsed date '{date_str}' as {fmt_name}: {result}")
                return result
            except ValueError as ve:
                logger.debug(f"Failed to parse date '{date_str}' with format {fmt_name}: {str(ve)}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error parsing date '{date_str}' with format {fmt_name}: {str(e)}")
                continue
                
        logger.warning(f"Failed to parse date string with any format: {date_str}")
        logger.debug(f"Available formats tried: {[fmt[0] for fmt in formats]}")
        
        # Last resort: Try to extract date from string if it contains something that looks like a date
        try:
            # Look for YYYY-MM-DD pattern
            import re
            match = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
            if match:
                result = datetime.strptime(match.group(1), '%Y-%m-%d')
                logger.debug(f"Extracted date from string using regex: {result}")
                return result
        except Exception as e:
            logger.debug(f"Failed to extract date using regex: {str(e)}")
        
        return None

    def _extract_organization(self, issuer_dn: str) -> str:
        """Extract organization from issuer DN."""
        if not issuer_dn:
            return ""
        # Simple extraction - look for O= in the DN
        for part in issuer_dn.split(','):
            part = part.strip()
            if part.startswith('O='):
                return part[2:]
        return ""

def search_certificates_by_dns(dns_name: str, exclude_expired: bool = False, **kwargs) -> List[Dict[str, Any]]:
    """Search for certificates by DNS name using crt.sh.
    
    Args:
        dns_name: DNS name to search for
        exclude_expired: If True, exclude expired certificates
        **kwargs: Additional arguments passed to search_certificates
        
    Returns:
        List of matching certificates
    """
    client = CRTshClient()
    return client.search_certificates(dns_name, exclude_expired=exclude_expired, **kwargs)
