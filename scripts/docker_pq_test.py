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
        self.oqs_openssl_image = "openquantumsafe/openssl"
        
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
        
        # PQ curves to test
        pq_curves = [
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
        
        # PQ groups to test
        pq_groups = [
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
    
    def comprehensive_test(self, hostname: str, port: int = 443) -> dict:
        """Run comprehensive PQ test using both tools."""
        print(f"\n🔍 Testing {hostname}:{port} with Docker-based PQ tools")
        print("=" * 60)
        
        results = {
            'hostname': hostname,
            'port': port,
            'docker_available': self.check_docker(),
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
    
    args = parser.parse_args()
    
    tester = DockerPQTester()
    
    # Pull images if requested
    if args.pull_images:
        if not tester.pull_images():
            print("Failed to pull required Docker images")
            sys.exit(1)
    
    # Run comprehensive test
    results = tester.comprehensive_test(args.hostname, args.port)
    
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