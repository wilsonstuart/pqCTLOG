"""
Client for interacting with Certificate Transparency logs.
"""
import json
import logging
import requests
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class CTLogClient:
    """Client for interacting with Certificate Transparency logs."""
    
    def __init__(self, base_url: str, timeout: int = 30):
        """Initialize the CT log client.
        
        Args:
            base_url: Base URL of the CT log server
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'pqCTLOG/0.1.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def get_log_info(self) -> Dict[str, Any]:
        """Get information about the CT log.
        
        Returns:
            Dictionary containing log information
        """
        return self._make_request('ct/v1/get-sth')
    
    def get_entries(self, start: int, end: int) -> List[Dict]:
        """Get entries from the CT log.
        
        Args:
            start: Start index (inclusive)
            end: End index (exclusive)
            
        Returns:
            List of log entries
        """
        if start < 0 or end <= start:
            raise ValueError("Invalid range: start must be >= 0 and end must be > start")
            
        try:
            response = self._make_request(
                'ct/v1/get-entries',
                params={'start': start, 'end': end - 1}
            )
            return response.get('entries', [])
        except Exception as e:
            logger.error(f"Failed to get entries {start}-{end}: {str(e)}")
            return []
    
    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict:
        """Make an HTTP request to the CT log API.
        
        Args:
            endpoint: API endpoint (relative to base URL)
            method: HTTP method
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            Parsed JSON response
            
        Raises:
            requests.RequestException: If the request fails
        """
        url = urljoin(f"{self.base_url}/", endpoint)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to {url} failed: {str(e)}")
            raise
