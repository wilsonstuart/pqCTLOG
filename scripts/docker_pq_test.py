#!/usr/bin/env python3
"""
Docker-based post-quantum TLS testing using OQS containers.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)


class DockerPQTester:
    """Docker-based PQ TLS tester using OQS containers."""
    
    def __init__(self):
        self.oqs_curl_image = "openquantumsafe/curl"
        self.oqs_openssl_image = "openquantumsafe/oqs-ossl3"
        self.version_info = {}
        
    def check_docker(self) -> bool:
        """Check if Docker is available."""
        try:
            subprocess.run(['docker', '--version'], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def pull_images(self) -> bool:
        """Pull required OQS Docker images."""
        images = [self.oqs_curl_image, self.oqs_openssl_image]
        
        for image in images:
            print(f"Pulling {image}...")
            try:
                subprocess.run(['docker', 'pull', image], 
                             check=True, capture_output=True)
                print(f"✅ {image} pulled successfully")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to pull {image}: {e}")
                return False
        
        return True
    
    def get_version_info(self) -> dict:
        """Get version information from OQS Docker containers."""
        version_info = {
            'docker_available': self.check_docker(),
            'curl_info': {},
            'openssl_info': {}
        }
        
        if not version_info['docker_available']:
            return version_info
        
        # Get curl version info
        print("🔍 Checking OQS curl version...")
        version_info['curl_info'] = self._get_curl_version_info()
        
        # Get OpenSSL version info
        print("🔍 Checking OQS OpenSSL version...")
        version_info['openssl_info'] = self._get_openssl_version_info()
        
        self.version_info = version_info
        return version_info
    
    def _get_curl_version_info(self) -> dict:
        """Get curl version and supported curves."""
        info = {
            'version': 'Unknown',
            'openssl_version': 'Unknown',
            'supported_curves': [],
            'pq_curves': [],
            'errors': []
        }
        
        try:
            # Get curl version
            result = subprocess.run([
                'docker', 'run', '--rm', self.oqs_curl_image,
                'curl', '--version'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                if lines:
                    info['version'] = lines[0].strip()
                
                # Look for OpenSSL version in output
                for line in lines:
                    if 'OpenSSL' in line:
                        info['openssl_version'] = line.strip()
                        break
            
        except Exception as e:
            info['errors'].append(f"Version check failed: {e}")
        
        try:
            # Get supported curves - try different approaches
            result = subprocess.run([
                'docker', 'run', '--rm', self.oqs_curl_image,
                'curl', '--curves', 'help'
            ], capture_output=True, text=True, timeout=10)
            
            # If that doesn't work, try listing available curves differently
            if result.returncode != 0 or not result.stdout.strip():
                result = subprocess.run([
                    'docker', 'run', '--rm', self.oqs_curl_image,
                    'curl', '--help', 'all'
                ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                curves = []
                pq_curves = []
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('Usage:') and ':' not in line:
                        curves.append(line)
                        # Check if it's a PQ curve
                        if any(pq in line.lower() for pq in ['kyber', 'mlkem', 'dilithium', 'mldsa', 'falcon', 'sphincs']):
                            pq_curves.append(line)
                
                info['supported_curves'] = curves
                info['pq_curves'] = pq_curves
            
        except Exception as e:
            info['errors'].append(f"Curves check failed: {e}")
        
        return info
    
    def _get_openssl_version_info(self) -> dict:
        """Get OpenSSL version and supported groups."""
        info = {
            'version': 'Unknown',
            'liboqs_version': 'Unknown',
            'supported_groups': [],
            'pq_groups': [],
            'errors': []
        }
        
        try:
            # Get OpenSSL version
            result = subprocess.run([
                'docker', 'run', '--rm', self.oqs_openssl_image,
                'openssl', 'version', '-a'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.startswith('OpenSSL'):
                        info['version'] = line.strip()
                    elif 'liboqs' in line.lower():
                        info['liboqs_version'] = line.strip()
            
        except Exception as e:
            info['errors'].append(f"Version check failed: {e}")
        
        try:
            # Get supported groups/curves
            result = subprocess.run([
                'docker', 'run', '--rm', self.oqs_openssl_image,
                'openssl', 'ecparam', '-list_curves'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                groups = []
                pq_groups = []
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        # Extract curve name (before the colon)
                        curve_name = line.split(':')[0].strip()
                        if curve_name:
                            groups.append(curve_name)
                            # Check if it's a PQ group
                            if any(pq in curve_name.lower() for pq in ['kyber', 'mlkem', 'dilithium', 'mldsa', 'falcon', 'sphincs']):
                                pq_groups.append(curve_name)
                
                info['supported_groups'] = groups
                info['pq_groups'] = pq_groups
            
        except Exception as e:
            info['errors'].append(f"Groups check failed: {e}")
        
        return info
    
    def test_specific_algorithms(self) -> dict:
        """Test specific PQ algorithms to see what actually works."""
        test_results = {
            'curl_algorithms': {},
            'openssl_algorithms': {}
        }
        
        # Test algorithms with curl
        test_curves = ['kyber512', 'kyber768', 'mlkem768', 'x25519mlkem768', 'X25519MLKEM768']
        print(f"\n🧪 Testing specific algorithms with curl...")
        
        for curve in test_curves:
            try:
                result = subprocess.run([
                    'docker', 'run', '--rm', self.oqs_curl_image,
                    'curl', '--curves', curve, '--connect-timeout', '5',
                    '-o', '/dev/null', 'https://httpbin.org/get'
                ], capture_output=True, text=True, timeout=15)
                
                test_results['curl_algorithms'][curve] = {
                    'supported': result.returncode == 0,
                    'error': result.stderr if result.returncode != 0 else None
                }
                
                status = "✅" if result.returncode == 0 else "❌"
                print(f"   {status} {curve}")
                
            except Exception as e:
                test_results['curl_algorithms'][curve] = {
                    'supported': False,
                    'error': str(e)
                }
                print(f"   ❌ {curve} (error: {e})")
        
        # Test algorithms with OpenSSL
        test_groups = ['kyber512', 'kyber768', 'mlkem768', 'x25519mlkem768']
        print(f"\n🧪 Testing specific algorithms with OpenSSL...")
        
        for group in test_groups:
            try:
                result = subprocess.run([
                    'docker', 'run', '--rm', self.oqs_openssl_image,
                    'openssl', 's_client', '-connect', 'httpbin.org:443',
                    '-groups', group, '-brief'
                ], input='', capture_output=True, text=True, timeout=15)
                
                # Check if the connection attempt shows the group is recognized
                output = result.stdout + result.stderr
                supported = ('unknown group' not in output.lower() and 
                           'invalid group' not in output.lower())
                
                test_results['openssl_algorithms'][group] = {
                    'supported': supported,
                    'output_snippet': output[:200] if output else None
                }
                
                status = "✅" if supported else "❌"
                print(f"   {status} {group}")
                
            except Exception as e:
                test_results['openssl_algorithms'][group] = {
                    'supported': False,
                    'error': str(e)
                }
                print(f"   ❌ {group} (error: {e})")
        
        return test_results
    
    def print_version_info(self, version_info: dict = None):
        """Print detailed version information."""
        if version_info is None:
            version_info = self.version_info
        
        print(f"\n{'='*60}")
        print("OQS Docker Container Version Information")
        print(f"{'='*60}")
        
        if not version_info.get('docker_available'):
            print("❌ Docker not available")
            return
        
        # Curl info
        curl_info = version_info.get('curl_info', {})
        print(f"\n🌐 OQS curl Container ({self.oqs_curl_image}):")
        print(f"   Version: {curl_info.get('version', 'Unknown')}")
        print(f"   OpenSSL: {curl_info.get('openssl_version', 'Unknown')}")
        
        pq_curves = curl_info.get('pq_curves', [])
        if pq_curves:
            print(f"   PQ Curves ({len(pq_curves)}):")
            for curve in pq_curves[:10]:  # Show first 10
                print(f"     • {curve}")
            if len(pq_curves) > 10:
                print(f"     ... and {len(pq_curves) - 10} more")
        else:
            print("   PQ Curves: None detected")
        
        if curl_info.get('errors'):
            print(f"   Errors: {', '.join(curl_info['errors'])}")
        
        # OpenSSL info
        openssl_info = version_info.get('openssl_info', {})
        print(f"\n🔒 OQS OpenSSL Container ({self.oqs_openssl_image}):")
        print(f"   Version: {openssl_info.get('version', 'Unknown')}")
        print(f"   liboqs: {openssl_info.get('liboqs_version', 'Unknown')}")
        
        pq_groups = openssl_info.get('pq_groups', [])
        if pq_groups:
            print(f"   PQ Groups ({len(pq_groups)}):")
            for group in pq_groups[:10]:  # Show first 10
                print(f"     • {group}")
            if len(pq_groups) > 10:
                print(f"     ... and {len(pq_groups) - 10} more")
        else:
            print("   PQ Groups: None detected")
        
        if openssl_info.get('errors'):
            print(f"   Errors: {', '.join(openssl_info['errors'])}")
        
        # Summary
        total_pq_algorithms = len(pq_curves) + len(pq_groups)
        print(f"\n📊 Summary:")
        print(f"   Total PQ algorithms available: {total_pq_algorithms}")
        print(f"   curl PQ curves: {len(pq_curves)}")
        print(f"   OpenSSL PQ groups: {len(pq_groups)}")
        
        # Check for X25519MLKEM768 specifically
        x25519mlkem768_variants = [
            'X25519MLKEM768', 'x25519mlkem768', 'X25519-MLKEM768', 
            'x25519-mlkem768', 'mlkem768'
        ]
        
        found_variants = []
        for variant in x25519mlkem768_variants:
            if (any(variant.lower() in curve.lower() for curve in pq_curves) or
                any(variant.lower() in group.lower() for group in pq_groups)):
                found_variants.append(variant)
        
        if found_variants:
            print(f"   🎯 X25519MLKEM768 variants found: {', '.join(found_variants)}")
        else:
            print(f"   ❌ X25519MLKEM768 variants: Not found in available algorithms")
    
    def test_with_curl(self, hostname: str, port: int = 443) -> dict:
        """Test PQ support using OQS curl in Docker."""
        results = {
            'tool': 'oqs-curl-docker',
            'hostname': hostname,
            'port': port,
            'pq_algorithms': [],
            'successful_tests': [],
            'failed_tests': [],
            'errors': []
        }
        
        # PQ curves to test (including NIST standardized names)
        pq_curves = [
            # NIST standardized ML-KEM (Kyber)
            'mlkem512',
            'mlkem768',
            'mlkem1024',
            # NIST standardized hybrid combinations
            'x25519mlkem768',
            'X25519MLKEM768',  # Alternative capitalization
            'p256mlkem768',
            'p384mlkem768',
            # Legacy Kyber names (still supported by some implementations)
            'kyber512',
            'kyber768', 
            'kyber1024',
            'x25519_kyber512',  # Hybrid
            'x25519_kyber768',  # Hybrid
            'p256_kyber512',    # Hybrid
            'p384_kyber768'     # Hybrid
        ]
        
        for curve in pq_curves:
            try:
                cmd = [
                    'docker', 'run', '--rm',
                    self.oqs_curl_image,
                    'curl', '-v', '--connect-timeout', '10',
                    '--curves', curve,
                    '-o', '/dev/null',
                    f'https://{hostname}:{port}/'
                ]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                
                if result.returncode == 0:
                    results['successful_tests'].append(curve)
                    results['pq_algorithms'].append(curve)
                    print(f"  ✅ {curve}: SUCCESS")
                else:
                    results['failed_tests'].append(curve)
                    print(f"  ❌ {curve}: Failed")
                    
            except subprocess.TimeoutExpired:
                results['failed_tests'].append(curve)
                results['errors'].append(f"{curve}: Timeout")
                print(f"  ⏰ {curve}: Timeout")
            except Exception as e:
                results['failed_tests'].append(curve)
                results['errors'].append(f"{curve}: {str(e)}")
                print(f"  ❌ {curve}: Error - {e}")
        
        return results
    
    def test_with_openssl(self, hostname: str, port: int = 443) -> dict:
        """Test PQ support using OQS OpenSSL in Docker."""
        results = {
            'tool': 'oqs-openssl-docker',
            'hostname': hostname,
            'port': port,
            'pq_algorithms': [],
            'successful_tests': [],
            'failed_tests': [],
            'connection_details': {},
            'errors': []
        }
        
        # PQ groups to test (including NIST standardized names)
        pq_groups = [
            # NIST standardized ML-KEM (Kyber)
            'mlkem512',
            'mlkem768', 
            'mlkem1024',
            # NIST standardized hybrid combinations
            'x25519mlkem768',
            'X25519MLKEM768',  # Alternative capitalization
            'p256mlkem768',
            'p384mlkem768',
            # NIST standardized ML-DSA (Dilithium)
            'mldsa44',
            'mldsa65',
            'mldsa87',
            # Legacy names (still supported by some implementations)
            'kyber512',
            'kyber768',
            'kyber1024', 
            'x25519_kyber512',
            'p256_kyber512',
            'dilithium2',
            'dilithium3',
            'falcon512'
        ]
        
        for group in pq_groups:
            try:
                cmd = [
                    'docker', 'run', '--rm',
                    self.oqs_openssl_image,
                    'openssl', 's_client',
                    '-connect', f'{hostname}:{port}',
                    '-servername', hostname,
                    '-groups', group,
                    '-brief'
                ]
                
                result = subprocess.run(
                    cmd,
                    input='',
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                
                output = result.stdout + result.stderr
                
                # Check for successful connection indicators
                if ('Verification: OK' in output or 
                    'Verify return code: 0' in output or
                    'Protocol  :' in output):
                    
                    results['successful_tests'].append(group)
                    results['pq_algorithms'].append(group)
                    results['connection_details'][group] = self._parse_openssl_output(output)
                    print(f"  ✅ {group}: SUCCESS")
                else:
                    results['failed_tests'].append(group)
                    print(f"  ❌ {group}: Failed")
                    
            except subprocess.TimeoutExpired:
                results['failed_tests'].append(group)
                results['errors'].append(f"{group}: Timeout")
                print(f"  ⏰ {group}: Timeout")
            except Exception as e:
                results['failed_tests'].append(group)
                results['errors'].append(f"{group}: {str(e)}")
                print(f"  ❌ {group}: Error - {e}")
        
        return results
    
    def _parse_openssl_output(self, output: str) -> dict:
        """Parse OpenSSL output for connection details."""
        details = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('Protocol'):
                details['protocol'] = line.split(':')[1].strip()
            elif line.startswith('Cipher'):
                details['cipher'] = line.split(':')[1].strip()
            elif 'Server public key' in line:
                details['server_key'] = line.split(':')[1].strip()
        
        return details
    
    def comprehensive_test(self, hostname: str, port: int = 443, show_versions: bool = True) -> dict:
        """Run comprehensive PQ test using both tools."""
        print(f"\n🔍 Testing {hostname}:{port} with Docker-based PQ tools")
        print("=" * 60)
        
        results = {
            'hostname': hostname,
            'port': port,
            'docker_available': self.check_docker(),
            'version_info': {},
            'curl_results': None,
            'openssl_results': None,
            'summary': {
                'pq_support_detected': False,
                'supported_algorithms': [],
                'hybrid_support': False
            }
        }
        
        if not results['docker_available']:
            print("❌ Docker not available")
            return results
        
        # Get version information first
        if show_versions:
            results['version_info'] = self.get_version_info()
            self.print_version_info(results['version_info'])
        
        # Test with curl
        print("\n🌐 Testing with OQS curl...")
        results['curl_results'] = self.test_with_curl(hostname, port)
        
        # Test with OpenSSL
        print("\n🔒 Testing with OQS OpenSSL...")
        results['openssl_results'] = self.test_with_openssl(hostname, port)
        
        # Compile summary
        all_algorithms = set()
        if results['curl_results']:
            all_algorithms.update(results['curl_results']['pq_algorithms'])
        if results['openssl_results']:
            all_algorithms.update(results['openssl_results']['pq_algorithms'])
        
        results['summary']['supported_algorithms'] = list(all_algorithms)
        results['summary']['pq_support_detected'] = len(all_algorithms) > 0
        results['summary']['hybrid_support'] = any(
            'x25519' in alg or 'p256' in alg or 'p384' in alg 
            for alg in all_algorithms
        )
        
        return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Docker-based Post-Quantum TLS Testing')
    parser.add_argument('hostname', help='Hostname to test')
    parser.add_argument('--port', type=int, default=443, help='Port to test')
    parser.add_argument('--pull-images', action='store_true', 
                       help='Pull Docker images before testing')
    parser.add_argument('--output', choices=['summary', 'detailed', 'json'],
                       default='detailed', help='Output format')
    parser.add_argument('--versions-only', action='store_true',
                       help='Only show version information, skip testing')
    parser.add_argument('--no-versions', action='store_true',
                       help='Skip version information display')
    parser.add_argument('--test-algorithms', action='store_true',
                       help='Test specific PQ algorithms to see what works')
    
    args = parser.parse_args()
    
    tester = DockerPQTester()
    
    # Pull images if requested
    if args.pull_images:
        if not tester.pull_images():
            print("Failed to pull required Docker images")
            sys.exit(1)
    
    # Handle versions-only mode
    if args.versions_only:
        version_info = tester.get_version_info()
        tester.print_version_info(version_info)
        return
    
    # Handle algorithm testing mode
    if args.test_algorithms:
        version_info = tester.get_version_info()
        tester.print_version_info(version_info)
        test_results = tester.test_specific_algorithms()
        return
    
    # Run comprehensive test
    results = tester.comprehensive_test(
        args.hostname, 
        args.port, 
        show_versions=not args.no_versions
    )
    
    # Output results
    if args.output == 'json':
        print(json.dumps(results, indent=2, default=str))
    elif args.output == 'summary':
        print_summary(results)
    else:  # detailed
        print_detailed(results)


def print_summary(results):
    """Print summary of results."""
    hostname = results['hostname']
    summary = results['summary']
    
    print(f"\n{'='*50}")
    print(f"PQ Test Summary for {hostname}")
    print(f"{'='*50}")
    
    pq_support = summary['pq_support_detected']
    print(f"🔒 Post-Quantum Support: {'✅ YES' if pq_support else '❌ NO'}")
    
    if pq_support:
        algorithms = summary['supported_algorithms']
        print(f"🔑 Supported Algorithms: {len(algorithms)}")
        for alg in algorithms:
            print(f"   • {alg}")
        
        hybrid = summary['hybrid_support']
        print(f"🔄 Hybrid Support: {'✅ YES' if hybrid else '❌ NO'}")


def print_detailed(results):
    """Print detailed results."""
    print_summary(results)
    
    # Curl results
    curl_results = results.get('curl_results')
    if curl_results:
        print(f"\n🌐 OQS curl Results:")
        successful = curl_results['successful_tests']
        failed = curl_results['failed_tests']
        print(f"   Successful: {len(successful)}")
        print(f"   Failed: {len(failed)}")
        
        if successful:
            print("   ✅ Working algorithms:")
            for alg in successful:
                print(f"      • {alg}")
    
    # OpenSSL results  
    openssl_results = results.get('openssl_results')
    if openssl_results:
        print(f"\n🔒 OQS OpenSSL Results:")
        successful = openssl_results['successful_tests']
        failed = openssl_results['failed_tests']
        print(f"   Successful: {len(successful)}")
        print(f"   Failed: {len(failed)}")
        
        if successful:
            print("   ✅ Working algorithms:")
            for alg in successful:
                details = openssl_results['connection_details'].get(alg, {})
                print(f"      • {alg}")
                if details:
                    for key, value in details.items():
                        print(f"        {key}: {value}")


if __name__ == "__main__":
    main()