"""
TLS scanner for analyzing cipher suites and TLS configurations.
"""
import logging
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse

from .pq_client import PQTLSClient

logger = logging.getLogger(__name__)


class TLSScanner:
    """Scanner for TLS configurations and cipher suites."""
    
    def __init__(self, config):
        """Initialize the TLS scanner.
        
        Args:
            config: Application configuration object
        """
        self.config = config.tls_scanner
        self.timeout = self.config.timeout
        self.max_workers = self.config.max_workers
        self.ports = self.config.ports
        self.tls_versions = self.config.tls_versions
        self.test_ciphersuites = self.config.ciphersuites
        self.post_quantum_ciphers = self.config.post_quantum_ciphers
        
        # Rate limiting
        self._last_scan_time = {}
        self._scan_lock = threading.Lock()
        
        # PQ client for advanced testing
        self.pq_client = PQTLSClient(config)
    
    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple domains for TLS configurations.
        
        Args:
            domains: List of domain names to scan
            
        Returns:
            List of scan results
        """
        if not domains:
            return []
        
        logger.info(f"Starting TLS scan of {len(domains)} domains")
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit scan tasks
            future_to_domain = {
                executor.submit(self.scan_domain, domain): domain 
                for domain in domains
            }
            
            # Collect results
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Error scanning domain {domain}: {e}")
                    results.append(self._create_error_result(domain, str(e)))
        
        logger.info(f"Completed TLS scan: {len(results)} results")
        return results
    
    def scan_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Scan a single domain for TLS configuration.
        
        Args:
            domain: Domain name to scan
            
        Returns:
            Scan result dictionary or None if scan failed
        """
        # Rate limiting per domain
        with self._scan_lock:
            last_scan = self._last_scan_time.get(domain, 0)
            time_since_last = time.time() - last_scan
            if time_since_last < 1.0:  # Minimum 1 second between scans per domain
                time.sleep(1.0 - time_since_last)
            self._last_scan_time[domain] = time.time()
        
        logger.debug(f"Scanning domain: {domain}")
        
        # Clean domain name (remove wildcards, protocols, etc.)
        clean_domain = self._clean_domain_name(domain)
        if not clean_domain:
            logger.warning(f"Invalid domain name: {domain}")
            return None
        
        scan_result = {
            'domain': clean_domain,
            'original_domain': domain,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'ports': {},
            'summary': {
                'total_ports_scanned': 0,
                'successful_connections': 0,
                'tls_versions_supported': set(),
                'cipher_suites_found': set(),
                'post_quantum_ready': False,
                'security_issues': []
            }
        }
        
        # Scan each configured port
        for port in self.ports:
            port_result = self._scan_port(clean_domain, port)
            scan_result['ports'][str(port)] = port_result
            scan_result['summary']['total_ports_scanned'] += 1
            
            if port_result.get('success'):
                scan_result['summary']['successful_connections'] += 1
                
                # Aggregate TLS versions
                if 'tls_versions' in port_result:
                    for version, supported in port_result['tls_versions'].items():
                        if supported:
                            scan_result['summary']['tls_versions_supported'].add(version)
                
                # Aggregate cipher suites
                if 'cipher_suites' in port_result:
                    for cipher in port_result['cipher_suites']:
                        scan_result['summary']['cipher_suites_found'].add(cipher['name'])
                
                # Check for post-quantum readiness
                pq_assessment = port_result.get('post_quantum_assessment', {})
                if pq_assessment.get('overall_assessment'):
                    scan_result['summary']['post_quantum_ready'] = True
                
                # Collect security issues
                if 'security_issues' in port_result:
                    scan_result['summary']['security_issues'].extend(port_result['security_issues'])
        
        # Convert sets to lists for JSON serialization
        scan_result['summary']['tls_versions_supported'] = list(scan_result['summary']['tls_versions_supported'])
        scan_result['summary']['cipher_suites_found'] = list(scan_result['summary']['cipher_suites_found'])
        
        return scan_result
    
    def _scan_port(self, domain: str, port: int) -> Dict[str, Any]:
        """Scan a specific port on a domain.
        
        Args:
            domain: Domain name to scan
            port: Port number to scan
            
        Returns:
            Port scan result dictionary
        """
        result = {
            'port': port,
            'success': False,
            'error': None,
            'connection_time': None,
            'certificate_info': None,
            'tls_versions': {},
            'cipher_suites': [],
            'preferred_cipher': None,
            'post_quantum_ready': False,
            'security_issues': []
        }
        
        start_time = time.time()
        
        try:
            # Test each TLS version
            for tls_version in self.tls_versions:
                version_supported, version_info = self._test_tls_version(domain, port, tls_version)
                result['tls_versions'][tls_version] = version_supported
                
                if version_supported and version_info:
                    # Get cipher suite information for this version
                    if not result['cipher_suites']:  # Only get detailed info once
                        result['cipher_suites'] = self._get_cipher_suites(domain, port, tls_version)
                        cipher_info = version_info.get('cipher')
                        if cipher_info:
                            result['preferred_cipher'] = {
                                'name': cipher_info[0],
                                'version': cipher_info[1], 
                                'bits': cipher_info[2]
                            }
                        result['certificate_info'] = version_info.get('certificate')
            
            # Check if any TLS version worked
            if any(result['tls_versions'].values()):
                result['success'] = True
                result['connection_time'] = time.time() - start_time
                
                # Analyze security
                result['security_issues'] = self._analyze_security_issues(result)
                result['post_quantum_assessment'] = self._check_post_quantum_readiness(result)
                
                # Test with PQ client if available
                if any(self.pq_client.available_tools.values()):
                    logger.debug(f"Testing PQ support for {domain}:{port}")
                    pq_result = self.pq_client.test_pq_support(domain, port)
                    result['pq_test_result'] = pq_result
                    
                    # Update PQ assessment based on actual testing
                    if pq_result.get('pq_support'):
                        result['post_quantum_assessment']['has_actual_pq_support'] = True
                        result['post_quantum_assessment']['pq_algorithms'] = pq_result.get('pq_algorithms', [])
                        result['post_quantum_assessment']['overall_assessment'] = True
                
                result['post_quantum_ready'] = result['post_quantum_assessment']['overall_assessment']
            else:
                result['error'] = 'No TLS versions supported or connection failed'
                
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Error scanning {domain}:{port} - {e}")
        
        return result
    
    def _test_tls_version(self, domain: str, port: int, tls_version: str) -> Tuple[bool, Optional[Dict]]:
        """Test if a specific TLS version is supported.
        
        Args:
            domain: Domain name
            port: Port number
            tls_version: TLS version to test (e.g., 'TLSv1.3')
            
        Returns:
            Tuple of (supported, connection_info)
        """
        try:
            # Map TLS version strings to SSL constants
            version_map = {
                'TLSv1.3': ssl.PROTOCOL_TLS,  # Will negotiate highest available
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.0': ssl.PROTOCOL_TLSv1,
                'SSLv3': ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None
            }
            
            protocol = version_map.get(tls_version)
            if protocol is None:
                return False, None
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # For specific version testing, we need to be more specific
            if tls_version == 'TLSv1.3':
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            elif tls_version == 'TLSv1.2':
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            elif tls_version == 'TLSv1.1':
                context.minimum_version = ssl.TLSVersion.TLSv1_1
                context.maximum_version = ssl.TLSVersion.TLSv1_1
            elif tls_version == 'TLSv1.0':
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1
            
            # Connect and get connection info
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    connection_info = {
                        'cipher': ssock.cipher(),
                        'version': ssock.version(),
                        'certificate': self._extract_cert_info(ssock.getpeercert())
                    }
                    return True, connection_info
                    
        except ssl.SSLError as e:
            # SSL-specific errors (version not supported, etc.)
            logger.debug(f"SSL error testing {tls_version} on {domain}:{port} - {e}")
            return False, None
        except (socket.timeout, socket.error, ConnectionRefusedError) as e:
            # Connection errors
            logger.debug(f"Connection error testing {tls_version} on {domain}:{port} - {e}")
            return False, None
        except Exception as e:
            # Other errors
            logger.debug(f"Unexpected error testing {tls_version} on {domain}:{port} - {e}")
            return False, None
    
    def _get_cipher_suites(self, domain: str, port: int, tls_version: str) -> List[Dict[str, Any]]:
        """Get supported cipher suites for a domain/port/version.
        
        Args:
            domain: Domain name
            port: Port number
            tls_version: TLS version to test
            
        Returns:
            List of supported cipher suites with details
        """
        cipher_suites = []
        
        try:
            # Create a context and get the default cipher list
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get cipher info
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_suites.append({
                            'name': cipher_info[0],
                            'version': cipher_info[1],
                            'bits': cipher_info[2],
                            'is_preferred': True,
                            'security_level': self._assess_cipher_security(cipher_info[0]),
                            'is_post_quantum': self._is_post_quantum_cipher(cipher_info[0])
                        })
            
        except Exception as e:
            logger.debug(f"Error getting cipher suites for {domain}:{port} - {e}")
        
        return cipher_suites
    
    def _extract_cert_info(self, cert_dict: Optional[Dict]) -> Optional[Dict[str, Any]]:
        """Extract relevant certificate information.
        
        Args:
            cert_dict: Certificate dictionary from SSL connection
            
        Returns:
            Simplified certificate information
        """
        if not cert_dict:
            return None
        
        return {
            'subject': dict(x[0] for x in cert_dict.get('subject', [])),
            'issuer': dict(x[0] for x in cert_dict.get('issuer', [])),
            'version': cert_dict.get('version'),
            'serial_number': cert_dict.get('serialNumber'),
            'not_before': cert_dict.get('notBefore'),
            'not_after': cert_dict.get('notAfter'),
            'subject_alt_names': [x[1] for x in cert_dict.get('subjectAltName', []) if x[0] == 'DNS']
        }
    
    def _assess_cipher_security(self, cipher_name: str) -> str:
        """Assess the security level of a cipher suite.
        
        Args:
            cipher_name: Name of the cipher suite
            
        Returns:
            Security level: 'secure', 'weak', 'insecure'
        """
        cipher_lower = cipher_name.lower()
        
        # TLS 1.3 ciphers are always secure
        if cipher_lower.startswith('tls_'):
            return 'secure'
        
        # Insecure ciphers (completely broken)
        insecure_patterns = ['rc4', 'des-', '_des_', 'md5', 'null', 'export']
        if any(pattern in cipher_lower for pattern in insecure_patterns):
            return 'insecure'
        
        # Weak ciphers (deprecated or problematic)
        weak_patterns = [
            '3des',           # Triple DES
            '_sha1',          # SHA-1 (but not SHA-256, SHA-384)
            '_cbc_sha',       # CBC with SHA-1
            'dhe_dss',        # DSS key exchange
            'adh_',           # Anonymous DH
            'aecdh_'          # Anonymous ECDH
        ]
        if any(pattern in cipher_lower for pattern in weak_patterns):
            return 'weak'
        
        # Modern secure ciphers
        secure_patterns = [
            'aes_gcm',        # AES-GCM
            'aes_ccm',        # AES-CCM  
            'chacha20',       # ChaCha20
            'poly1305',       # Poly1305
            '_sha256',        # SHA-256
            '_sha384',        # SHA-384
            'ecdhe-rsa-aes',  # ECDHE-RSA with AES
            'ecdhe-ecdsa-aes', # ECDHE-ECDSA with AES
            'dhe-rsa-aes'     # DHE-RSA with AES
        ]
        if any(pattern in cipher_lower for pattern in secure_patterns):
            return 'secure'
        
        # If we can't classify it, be conservative and call it weak
        return 'weak'
    
    def _is_post_quantum_cipher(self, cipher_name: str) -> bool:
        """Check if a cipher suite is post-quantum ready.
        
        Args:
            cipher_name: Name of the cipher suite
            
        Returns:
            True if post-quantum ready
        """
        cipher_lower = cipher_name.lower()
        return any(pq in cipher_lower for pq in [name.lower() for name in self.post_quantum_ciphers])
    
    def _analyze_security_issues(self, port_result: Dict[str, Any]) -> List[str]:
        """Analyze scan results for security issues.
        
        Args:
            port_result: Port scan result
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Check for insecure TLS versions
        tls_versions = port_result.get('tls_versions', {})
        if tls_versions.get('SSLv3'):
            issues.append('SSLv3 supported (insecure)')
        if tls_versions.get('TLSv1.0'):
            issues.append('TLSv1.0 supported (deprecated)')
        if tls_versions.get('TLSv1.1'):
            issues.append('TLSv1.1 supported (deprecated)')
        
        # Check cipher suites
        cipher_suites = port_result.get('cipher_suites', [])
        for cipher in cipher_suites:
            if cipher.get('security_level') == 'insecure':
                issues.append(f'Insecure cipher: {cipher["name"]}')
            elif cipher.get('security_level') == 'weak':
                issues.append(f'Weak cipher: {cipher["name"]}')
        
        # Check if only modern TLS is supported
        modern_tls = tls_versions.get('TLSv1.3') or tls_versions.get('TLSv1.2')
        if not modern_tls:
            issues.append('No modern TLS versions supported')
        
        return issues
    
    def _check_post_quantum_readiness(self, port_result: Dict[str, Any]) -> Dict[str, Any]:
        """Check if the configuration is post-quantum ready.
        
        Args:
            port_result: Port scan result
            
        Returns:
            Dictionary with PQ readiness information
        """
        cipher_suites = port_result.get('cipher_suites', [])
        has_pq_ciphers = any(cipher.get('is_post_quantum', False) for cipher in cipher_suites)
        
        # Check for indicators of potential PQ support
        pq_indicators = self._check_pq_indicators(port_result)
        
        return {
            'has_pq_ciphers': has_pq_ciphers,
            'pq_indicators': pq_indicators,
            'overall_assessment': has_pq_ciphers or len(pq_indicators) > 0,
            'limitations': [
                "Client does not support PQ key exchange - hybrid PQ may be available but not detectable",
                "Only cipher suite names are analyzed - actual key exchange algorithms not visible"
            ] if not has_pq_ciphers else []
        }
    
    def _check_pq_indicators(self, port_result: Dict[str, Any]) -> List[str]:
        """Check for indicators that might suggest PQ support.
        
        Args:
            port_result: Port scan result
            
        Returns:
            List of PQ indicators found
        """
        indicators = []
        
        # Check certificate info for PQ-related extensions or issuers
        cert_info = port_result.get('certificate_info', {})
        if cert_info:
            issuer = cert_info.get('issuer', {})
            
            # Cloudflare often supports hybrid PQ
            if any('cloudflare' in str(v).lower() for v in issuer.values()):
                indicators.append("Cloudflare certificate (may support hybrid PQ key exchange)")
            
            # Google also supports PQ experiments
            if any('google' in str(v).lower() for v in issuer.values()):
                indicators.append("Google certificate (may support experimental PQ)")
            
            # Check for modern TLS 1.3 support (prerequisite for most PQ)
            tls_versions = port_result.get('tls_versions', {})
            if tls_versions.get('TLSv1.3'):
                indicators.append("TLS 1.3 supported (enables PQ key exchange)")
            
            # Check for ECDHE support (often used in hybrid PQ)
            cipher_suites = port_result.get('cipher_suites', [])
            has_ecdhe = any('ecdhe' in cipher.get('name', '').lower() for cipher in cipher_suites)
            if has_ecdhe:
                indicators.append("ECDHE supported (compatible with hybrid PQ)")
        
        return indicators
    
    def _clean_domain_name(self, domain: str) -> Optional[str]:
        """Clean and validate domain name.
        
        Args:
            domain: Raw domain name
            
        Returns:
            Cleaned domain name or None if invalid
        """
        if not domain:
            return None
        
        # Remove wildcards
        domain = domain.replace('*.', '')
        
        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(f'http://{domain}').netloc or urlparse(domain).netloc
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Basic validation
        if not domain or '.' not in domain or len(domain) > 253:
            return None
        
        return domain.lower().strip()
    
    def _create_error_result(self, domain: str, error: str) -> Dict[str, Any]:
        """Create an error result for a failed scan.
        
        Args:
            domain: Domain that failed
            error: Error message
            
        Returns:
            Error result dictionary
        """
        return {
            'domain': domain,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'error': error,
            'ports': {},
            'summary': {
                'total_ports_scanned': 0,
                'successful_connections': 0,
                'tls_versions_supported': [],
                'cipher_suites_found': [],
                'post_quantum_ready': False,
                'security_issues': [f'Scan failed: {error}']
            }
        }