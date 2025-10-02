"""
Post-quantum capable TLS client using external tools.
"""
import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


class PQTLSClient:
    """Post-quantum capable TLS client using external tools."""
    
    def __init__(self, config):
        """Initialize the PQ TLS client.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.timeout = getattr(config.tls_scanner, 'timeout', 10)
        self.available_tools = self._detect_available_tools()
        
    def _detect_available_tools(self) -> Dict[str, bool]:
        """Detect which PQ-capable tools are available."""
        tools = {}
        
        # Check for OQS-enabled OpenSSL
        try:
            result = subprocess.run(
                ['openssl', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Look for OQS indicators in version string
            tools['openssl_oqs'] = 'OQS' in result.stdout or self._test_oqs_openssl()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['openssl_oqs'] = False
        
        # Check for OQS-enabled curl
        try:
            result = subprocess.run(
                ['curl', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Check if curl supports --curves option (needed for PQ)
            tools['curl_oqs'] = '--curves' in result.stdout or self._test_oqs_curl()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            tools['curl_oqs'] = False
        
        # Check for custom PQ tools
        tools['oqs_test_client'] = self._check_oqs_test_client()
        
        logger.info(f"Available PQ tools: {tools}")
        return tools
    
    def _test_oqs_openssl(self) -> bool:
        """Test if OpenSSL supports OQS groups."""
        try:
            # Try to list supported groups - OQS OpenSSL will show PQ groups
            result = subprocess.run(
                ['openssl', 'ecparam', '-list_curves'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Look for common PQ group names
            pq_indicators = ['kyber', 'dilithium', 'falcon', 'sphincs']
            return any(indicator in result.stdout.lower() for indicator in pq_indicators)
        except Exception:
            return False
    
    def _test_oqs_curl(self) -> bool:
        """Test if curl supports PQ curves."""
        try:
            # Try to use a PQ curve - will fail gracefully if not supported
            result = subprocess.run(
                ['curl', '--curves', 'help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Look for PQ curve names in help output
            pq_indicators = ['kyber', 'dilithium', 'falcon']
            return any(indicator in result.stdout.lower() for indicator in pq_indicators)
        except Exception:
            return False
    
    def _check_oqs_test_client(self) -> bool:
        """Check for OQS test client binary."""
        # Common locations for OQS test clients
        possible_paths = [
            '/usr/local/bin/oqs_test_client',
            '/opt/oqs/bin/test_client',
            './oqs_test_client',
            Path.home() / 'oqs' / 'bin' / 'test_client'
        ]
        
        for path in possible_paths:
            if Path(path).exists() and Path(path).is_file():
                return True
        return False
    
    def test_pq_support(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Test post-quantum support for a hostname.
        
        Args:
            hostname: Target hostname
            port: Target port
            
        Returns:
            Dictionary with PQ test results
        """
        results = {
            'hostname': hostname,
            'port': port,
            'timestamp': time.time(),
            'pq_support': False,
            'pq_algorithms': [],
            'hybrid_support': False,
            'tool_results': {},
            'errors': []
        }
        
        # Test with each available tool
        if self.available_tools.get('openssl_oqs'):
            openssl_result = self._test_with_openssl_oqs(hostname, port)
            results['tool_results']['openssl_oqs'] = openssl_result
            if openssl_result.get('success'):
                results['pq_support'] = True
                results['pq_algorithms'].extend(openssl_result.get('algorithms', []))
        
        if self.available_tools.get('curl_oqs'):
            curl_result = self._test_with_curl_oqs(hostname, port)
            results['tool_results']['curl_oqs'] = curl_result
            if curl_result.get('success'):
                results['pq_support'] = True
                results['pq_algorithms'].extend(curl_result.get('algorithms', []))
        
        # Deduplicate algorithms
        results['pq_algorithms'] = list(set(results['pq_algorithms']))
        
        # Check for hybrid support (classical + PQ)
        results['hybrid_support'] = any(
            'hybrid' in alg.lower() or 'x25519' in alg.lower() 
            for alg in results['pq_algorithms']
        )
        
        return results
    
    def _test_with_openssl_oqs(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test PQ support using OQS-enabled OpenSSL."""
        result = {
            'tool': 'openssl_oqs',
            'success': False,
            'algorithms': [],
            'connection_info': {},
            'error': None
        }
        
        # Common PQ groups to test
        pq_groups = [
            'kyber512',
            'kyber768', 
            'kyber1024',
            'x25519_kyber512',  # Hybrid
            'x25519_kyber768',  # Hybrid
            'p256_kyber512',    # Hybrid
            'dilithium2',
            'dilithium3',
            'falcon512',
            'falcon1024'
        ]
        
        for group in pq_groups:
            try:
                # Test connection with specific PQ group
                cmd = [
                    'openssl', 's_client',
                    '-connect', f'{hostname}:{port}',
                    '-servername', hostname,
                    '-groups', group,
                    '-brief',
                    '-verify_return_error'
                ]
                
                process = subprocess.run(
                    cmd,
                    input='',
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                
                if process.returncode == 0:
                    result['success'] = True
                    result['algorithms'].append(group)
                    
                    # Parse connection info
                    output = process.stdout + process.stderr
                    if 'Verification: OK' in output or 'Verify return code: 0' in output:
                        result['connection_info'][group] = self._parse_openssl_output(output)
                
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout testing {group} with OpenSSL")
            except Exception as e:
                logger.debug(f"Error testing {group} with OpenSSL: {e}")
        
        if not result['success']:
            result['error'] = 'No PQ groups successfully negotiated'
        
        return result
    
    def _test_with_curl_oqs(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test PQ support using OQS-enabled curl."""
        result = {
            'tool': 'curl_oqs',
            'success': False,
            'algorithms': [],
            'connection_info': {},
            'error': None
        }
        
        # Test with curl and PQ curves
        pq_curves = [
            'kyber512',
            'kyber768',
            'x25519_kyber512',
            'p256_kyber512'
        ]
        
        for curve in pq_curves:
            try:
                cmd = [
                    'curl',
                    '-v',
                    '--curves', curve,
                    '--connect-timeout', str(self.timeout),
                    '--max-time', str(self.timeout * 2),
                    '-o', '/dev/null',
                    f'https://{hostname}:{port}/'
                ]
                
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout * 2
                )
                
                # Check if connection succeeded (curl returns 0 for successful HTTPS)
                if process.returncode == 0:
                    result['success'] = True
                    result['algorithms'].append(curve)
                    
                    # Parse curl verbose output
                    stderr = process.stderr
                    result['connection_info'][curve] = self._parse_curl_output(stderr)
                
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout testing {curve} with curl")
            except Exception as e:
                logger.debug(f"Error testing {curve} with curl: {e}")
        
        if not result['success']:
            result['error'] = 'No PQ curves successfully negotiated'
        
        return result
    
    def _parse_openssl_output(self, output: str) -> Dict[str, Any]:
        """Parse OpenSSL s_client output for connection details."""
        info = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if line.startswith('Protocol'):
                info['protocol'] = line.split(':')[1].strip()
            elif line.startswith('Cipher'):
                info['cipher'] = line.split(':')[1].strip()
            elif line.startswith('Server public key'):
                info['server_key'] = line.split(':')[1].strip()
            elif 'Peer signature type' in line:
                info['signature_type'] = line.split(':')[1].strip()
        
        return info
    
    def _parse_curl_output(self, stderr: str) -> Dict[str, Any]:
        """Parse curl verbose output for connection details."""
        info = {}
        
        lines = stderr.split('\n')
        for line in lines:
            line = line.strip()
            
            if 'SSL connection using' in line:
                # Extract TLS version and cipher
                parts = line.split('SSL connection using')[1].strip()
                info['ssl_info'] = parts
            elif 'Server certificate:' in line:
                info['has_server_cert'] = True
            elif 'subject:' in line:
                info['subject'] = line.split('subject:')[1].strip()
        
        return info
    
    def get_available_tools_info(self) -> Dict[str, Any]:
        """Get information about available PQ tools."""
        return {
            'available_tools': self.available_tools,
            'recommendations': self._get_tool_recommendations()
        }
    
    def _get_tool_recommendations(self) -> List[str]:
        """Get recommendations for installing PQ tools."""
        recommendations = []
        
        if not any(self.available_tools.values()):
            recommendations.append(
                "No PQ-capable tools detected. Consider installing:"
            )
            recommendations.extend([
                "1. OQS-OpenSSL: https://github.com/open-quantum-safe/openssl",
                "2. OQS-curl: https://github.com/open-quantum-safe/curl", 
                "3. Docker image: openquantumsafe/curl"
            ])
        
        if not self.available_tools.get('openssl_oqs'):
            recommendations.append(
                "Install OQS-OpenSSL for comprehensive PQ testing"
            )
        
        if not self.available_tools.get('curl_oqs'):
            recommendations.append(
                "Install OQS-curl for web-based PQ testing"
            )
        
        return recommendations


def create_pq_test_script() -> str:
    """Create a standalone PQ test script."""
    script_content = '''#!/bin/bash
# Standalone Post-Quantum TLS Test Script
# Tests a hostname for PQ support using available tools

HOSTNAME="$1"
PORT="${2:-443}"

if [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 <hostname> [port]"
    exit 1
fi

echo "Testing $HOSTNAME:$PORT for Post-Quantum TLS support"
echo "=================================================="

# Test with OpenSSL (if OQS-enabled)
echo "Testing with OpenSSL..."
for group in kyber512 kyber768 x25519_kyber512 p256_kyber512; do
    echo -n "  Testing $group: "
    if timeout 10 openssl s_client -connect "$HOSTNAME:$PORT" -servername "$HOSTNAME" -groups "$group" -brief < /dev/null 2>/dev/null | grep -q "Verification: OK\\|Verify return code: 0"; then
        echo "✅ SUCCESS"
    else
        echo "❌ Failed"
    fi
done

# Test with curl (if OQS-enabled)
echo "Testing with curl..."
for curve in kyber512 kyber768 x25519_kyber512; do
    echo -n "  Testing $curve: "
    if timeout 10 curl -s --curves "$curve" "https://$HOSTNAME:$PORT/" > /dev/null 2>&1; then
        echo "✅ SUCCESS"
    else
        echo "❌ Failed"
    fi
done

echo "=================================================="
echo "Note: Failures may indicate:"
echo "- Server doesn't support that PQ algorithm"
echo "- Client tools don't have PQ support compiled in"
echo "- Network/connectivity issues"
'''
    return script_content