"""
Simplified crt.sh client for certificate searches.
"""
import logging
import random
import time
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.certificate_parser import parse_certificate_pem

logger = logging.getLogger(__name__)


class CRTshError(Exception):
    """Base exception for crt.sh related errors."""
    pass


class SimplifiedCRTshClient:
    """Simplified client for interacting with crt.sh."""
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self, rate_limit_delay: float = 1.0, timeout: int = 30):
        """Initialize the client.
        
        Args:
            rate_limit_delay: Delay between requests in seconds
            timeout: Request timeout in seconds
        """
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout
        self.session = self._create_session()
        self._last_request_time = 0
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'pqCTLOG/1.0',
            'Accept': 'application/json'
        })
        
        return session
    
    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        
        sleep_time = max(0, self.rate_limit_delay - elapsed)
        if sleep_time > 0:
            # Add jitter to prevent thundering herd
            sleep_time *= (0.8 + 0.4 * random.random())
            time.sleep(sleep_time)
        
        self._last_request_time = time.monotonic()
    
    def search_certificates(self, dns_name: str, exclude_expired: bool = False, 
                          exclude_precerts: bool = True, download_full_certs: bool = False) -> List[Dict[str, Any]]:
        """Search for certificates by DNS name.
        
        Args:
            dns_name: Domain name to search for
            exclude_expired: Whether to exclude expired certificates
            exclude_precerts: Whether to exclude pre-certificates
            download_full_certs: Whether to download and parse full certificate details
            
        Returns:
            List of certificate information dictionaries
        """
        self._rate_limit()
        
        params = {
            'q': f'%.{dns_name}',
            'output': 'json'
        }
        
        if exclude_expired:
            params['exclude'] = 'expired'
        
        try:
            response = self.session.get(
                f"{self.BASE_URL}/",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            certificates = response.json()
            if not isinstance(certificates, list):
                logger.warning(f"Unexpected response format: {type(certificates)}")
                return []
            
            logger.info(f"Found {len(certificates)} certificates for {dns_name}")
            
            # Process certificates
            processed = []
            for cert_data in certificates:
                try:
                    # Skip pre-certificates if requested
                    if exclude_precerts and cert_data.get('entry_type') == 'Precertificate':
                        continue
                    
                    processed_cert = self._process_certificate(cert_data, download_full_cert=download_full_certs)
                    if processed_cert:
                        processed.append(processed_cert)
                        
                except Exception as e:
                    logger.warning(f"Error processing certificate {cert_data.get('id')}: {e}")
                    continue
            
            logger.info(f"Successfully processed {len(processed)} certificates")
            return processed
            
        except requests.RequestException as e:
            logger.error(f"Error searching certificates: {e}")
            raise CRTshError(f"Failed to search certificates: {e}")
    
    def _process_certificate(self, cert_data: Dict[str, Any], download_full_cert: bool = False) -> Optional[Dict[str, Any]]:
        """Process a certificate from crt.sh response."""
        try:
            # Extract basic information from crt.sh response
            from src.core.utils import safe_parse_date
            from datetime import datetime
            
            # Parse validity dates and check if certificate is currently valid
            not_before = safe_parse_date(cert_data.get('not_before', ''))
            not_after = safe_parse_date(cert_data.get('not_after', ''))
            now = datetime.utcnow()
            is_valid = False
            days_remaining = 0
            
            if not_before and not_after:
                is_valid = not_before <= now <= not_after
                if not_after > now:
                    days_remaining = (not_after - now).days
            
            result = {
                'id': cert_data.get('id'),
                'serial_number': cert_data.get('serial_number', ''),
                'issuer': self._parse_dn_string(cert_data.get('issuer_name', '')),
                'subject': self._build_subject_from_crtsh(cert_data),
                'validity': {
                    'not_before': cert_data.get('not_before', ''),
                    'not_after': cert_data.get('not_after', ''),
                    'is_valid': is_valid,
                    'days_remaining': days_remaining
                },
                'is_precertificate': cert_data.get('entry_type') == 'Precertificate',
                'entry_type': cert_data.get('entry_type', ''),
                'subject_alternative_names': self._extract_sans(cert_data.get('name_value', '')),
                'issuer_ca_id': cert_data.get('issuer_ca_id'),
                'entry_timestamp': cert_data.get('entry_timestamp', ''),
                # Basic signature algorithm info (will be unknown without full cert download)
                'signature_algorithm': {
                    'name': 'unknown',
                    'is_quantum_vulnerable': False,
                    'is_post_quantum': False,
                    'pq_algorithm_type': None,
                    'security_level': None
                },
                'public_key': {
                    'type': 'unknown',
                    'size': 0,
                    'details': {}
                },
                # Metadata about the data source
                'data_source': 'crt.sh_search',
                'full_cert_downloaded': False
            }
            
            # Only download and parse the full certificate if requested
            if download_full_cert and cert_data.get('id'):
                full_cert = self._download_certificate(cert_data['id'])
                if full_cert:
                    # Merge the detailed information
                    result.update(full_cert)
                    # Preserve the original ID and basic info
                    result['id'] = cert_data.get('id')
                    result['is_precertificate'] = cert_data.get('entry_type') == 'Precertificate'
                    result['data_source'] = 'crt.sh_full'
                    result['full_cert_downloaded'] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing certificate: {e}")
            return None
    
    def download_certificate(self, cert_id: int) -> Optional[Dict[str, Any]]:
        """Public method to download a specific certificate by ID."""
        return self._download_certificate(cert_id)
    
    def _download_certificate(self, cert_id: int) -> Optional[Dict[str, Any]]:
        """Download and parse a certificate by ID."""
        try:
            self._rate_limit()
            
            response = self.session.get(
                f"{self.BASE_URL}/?d={cert_id}",
                timeout=self.timeout
            )
            response.raise_for_status()
            
            cert_pem = response.text.strip()
            if '-----BEGIN CERTIFICATE-----' not in cert_pem:
                return None
            
            return parse_certificate_pem(cert_pem, cert_id)
            
        except Exception as e:
            logger.debug(f"Could not download certificate {cert_id}: {e}")
            return None
    
    def _parse_dn_string(self, dn_string: str) -> Dict[str, str]:
        """Parse a distinguished name string."""
        result = {}
        
        if not dn_string:
            return result
        
        # Handle multi-line DN strings (common in crt.sh)
        dn_string = dn_string.replace('\n', ', ')
        
        # Parse DN components
        for part in dn_string.split(','):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Map common abbreviations
                key_mapping = {
                    'CN': 'commonName',
                    'O': 'organizationName',
                    'OU': 'organizationalUnitName', 
                    'C': 'countryName',
                    'ST': 'stateOrProvinceName',
                    'L': 'localityName'
                }
                
                result[key_mapping.get(key, key)] = value
        
        return result
    
    def _build_subject_from_crtsh(self, cert_data: Dict[str, Any]) -> Dict[str, str]:
        """Build subject information from crt.sh response data."""
        subject = {}
        
        # The common_name field in crt.sh contains the primary CN
        common_name = cert_data.get('common_name', '')
        if common_name:
            subject['commonName'] = common_name
        
        # If we don't have a common_name, try to extract it from name_value
        if not common_name:
            name_value = cert_data.get('name_value', '')
            if name_value:
                # The first line of name_value is usually the primary domain
                first_name = name_value.split('\n')[0].strip()
                if first_name:
                    subject['commonName'] = first_name
        
        # For now, we don't have other subject fields from the basic crt.sh search
        # These would only be available if we download the full certificate
        return subject
    
    def _extract_sans(self, name_value: str) -> List[str]:
        """Extract Subject Alternative Names from name_value field."""
        if not name_value:
            return []
        
        # Split by newlines and clean up
        names = [name.strip() for name in name_value.split('\n') if name.strip()]
        
        # Filter out non-DNS names and duplicates
        dns_names = []
        seen = set()
        
        for name in names:
            # Skip if it looks like an email or IP
            if '@' in name or name.replace('.', '').replace(':', '').isdigit():
                continue
            
            # Basic domain validation
            if '.' in name and len(name) < 254 and name not in seen:
                dns_names.append(name)
                seen.add(name)
        
        return dns_names