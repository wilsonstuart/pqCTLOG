#!/usr/bin/env python3
"""
Specific test for X25519MLKEM768 hybrid post-quantum key exchange.
"""
import argparse
import subprocess
import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def test_x25519mlkem768_variants(hostname: str, port: int = 443):
    """Test different variants of X25519MLKEM768 naming."""
    
    # Different possible names for X25519+ML-KEM-768
    variants = [
        'X25519MLKEM768',      # Your specific request
        'x25519mlkem768',      # Lowercase version
        'X25519-MLKEM768',     # With dash
        'x25519-mlkem768',     # Lowercase with dash
        'X25519_MLKEM768',     # With underscore
        'x25519_mlkem768',     # Lowercase with underscore
        'mlkem768',            # Just ML-KEM-768
        'x25519+mlkem768',     # With plus sign
        'hybrid_x25519_mlkem768'  # Explicit hybrid naming
    ]
    
    print(f"Testing X25519MLKEM768 variants for {hostname}:{port}")
    print("=" * 60)
    
    results = {
        'hostname': hostname,
        'port': port,
        'successful_variants': [],
        'failed_variants': [],
        'tool_results': {}
    }
    
    # Test with Docker OQS curl if available
    print("\n🐳 Testing with Docker OQS curl...")
    docker_results = test_with_docker_curl(hostname, port, variants)
    results['tool_results']['docker_curl'] = docker_results
    
    # Test with local OQS curl if available
    print("\n🌐 Testing with local OQS curl...")
    local_curl_results = test_with_local_curl(hostname, port, variants)
    results['tool_results']['local_curl'] = local_curl_results
    
    # Test with local OQS OpenSSL if available
    print("\n🔒 Testing with local OQS OpenSSL...")
    openssl_results = test_with_local_openssl(hostname, port, variants)
    results['tool_results']['local_openssl'] = openssl_results
    
    # Compile overall results
    for tool_result in results['tool_results'].values():
        results['successful_variants'].extend(tool_result.get('successful', []))
        results['failed_variants'].extend(tool_result.get('failed', []))
    
    # Remove duplicates
    results['successful_variants'] = list(set(results['successful_variants']))
    results['failed_variants'] = list(set(results['failed_variants']))
    
    return results


def test_with_docker_curl(hostname: str, port: int, variants: list) -> dict:
    """Test with Docker OQS curl."""
    results = {'tool': 'docker_curl', 'successful': [], 'failed': [], 'errors': []}
    
    # Check if Docker is available
    try:
        subprocess.run(['docker', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        results['errors'].append("Docker not available")
        print("  ❌ Docker not available")
        return results
    
    for variant in variants:
        try:
            cmd = [
                'docker', 'run', '--rm',
                'openquantumsafe/curl',
                'curl', '-v', '--connect-timeout', '10',
                '--curves', variant,
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
                results['successful'].append(variant)
                print(f"  ✅ {variant}: SUCCESS")
            else:
                results['failed'].append(variant)
                print(f"  ❌ {variant}: Failed")
                
        except subprocess.TimeoutExpired:
            results['failed'].append(variant)
            results['errors'].append(f"{variant}: Timeout")
            print(f"  ⏰ {variant}: Timeout")
        except Exception as e:
            results['failed'].append(variant)
            results['errors'].append(f"{variant}: {str(e)}")
            print(f"  ❌ {variant}: Error - {e}")
    
    return results


def test_with_local_curl(hostname: str, port: int, variants: list) -> dict:
    """Test with local OQS curl."""
    results = {'tool': 'local_curl', 'successful': [], 'failed': [], 'errors': []}
    
    # Check if curl supports --curves
    try:
        result = subprocess.run(['curl', '--curves', 'help'], 
                              capture_output=True, text=True, timeout=5)
        if 'kyber' not in result.stdout.lower() and 'mlkem' not in result.stdout.lower():
            results['errors'].append("Local curl doesn't appear to support PQ curves")
            print("  ❌ Local curl doesn't support PQ curves")
            return results
    except Exception:
        results['errors'].append("Local curl not available or doesn't support --curves")
        print("  ❌ Local curl not available")
        return results
    
    for variant in variants:
        try:
            cmd = [
                'curl', '-v', '--connect-timeout', '10',
                '--curves', variant,
                '-o', '/dev/null',
                f'https://{hostname}:{port}/'
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=20
            )
            
            if result.returncode == 0:
                results['successful'].append(variant)
                print(f"  ✅ {variant}: SUCCESS")
            else:
                results['failed'].append(variant)
                print(f"  ❌ {variant}: Failed")
                
        except subprocess.TimeoutExpired:
            results['failed'].append(variant)
            print(f"  ⏰ {variant}: Timeout")
        except Exception as e:
            results['failed'].append(variant)
            print(f"  ❌ {variant}: Error - {e}")
    
    return results


def test_with_local_openssl(hostname: str, port: int, variants: list) -> dict:
    """Test with local OQS OpenSSL."""
    results = {'tool': 'local_openssl', 'successful': [], 'failed': [], 'errors': []}
    
    # Check if OpenSSL supports PQ groups
    try:
        result = subprocess.run(['openssl', 'ecparam', '-list_curves'], 
                              capture_output=True, text=True, timeout=5)
        if 'kyber' not in result.stdout.lower() and 'mlkem' not in result.stdout.lower():
            results['errors'].append("Local OpenSSL doesn't appear to support PQ groups")
            print("  ❌ Local OpenSSL doesn't support PQ groups")
            return results
    except Exception:
        results['errors'].append("Local OpenSSL not available")
        print("  ❌ Local OpenSSL not available")
        return results
    
    for variant in variants:
        try:
            cmd = [
                'openssl', 's_client',
                '-connect', f'{hostname}:{port}',
                '-servername', hostname,
                '-groups', variant,
                '-brief'
            ]
            
            result = subprocess.run(
                cmd,
                input='',
                capture_output=True,
                text=True,
                timeout=15
            )
            
            output = result.stdout + result.stderr
            
            # Check for successful connection indicators
            if ('Verification: OK' in output or 
                'Verify return code: 0' in output or
                'Protocol  :' in output):
                
                results['successful'].append(variant)
                print(f"  ✅ {variant}: SUCCESS")
            else:
                results['failed'].append(variant)
                print(f"  ❌ {variant}: Failed")
                
        except subprocess.TimeoutExpired:
            results['failed'].append(variant)
            print(f"  ⏰ {variant}: Timeout")
        except Exception as e:
            results['failed'].append(variant)
            print(f"  ❌ {variant}: Error - {e}")
    
    return results


def print_summary(results):
    """Print summary of test results."""
    hostname = results['hostname']
    successful = results['successful_variants']
    failed = results['failed_variants']
    
    print(f"\n{'='*60}")
    print(f"X25519MLKEM768 Test Summary for {hostname}")
    print(f"{'='*60}")
    
    if successful:
        print(f"✅ Successful variants ({len(successful)}):")
        for variant in successful:
            print(f"   • {variant}")
    else:
        print("❌ No successful variants found")
    
    if failed:
        print(f"\n❌ Failed variants ({len(failed)}):")
        for variant in failed[:5]:  # Show first 5
            print(f"   • {variant}")
        if len(failed) > 5:
            print(f"   ... and {len(failed) - 5} more")
    
    # Show tool-specific results
    print(f"\n🔧 Tool Results:")
    for tool, tool_result in results['tool_results'].items():
        successful_count = len(tool_result.get('successful', []))
        total_count = successful_count + len(tool_result.get('failed', []))
        print(f"   {tool}: {successful_count}/{total_count} successful")
        
        errors = tool_result.get('errors', [])
        if errors:
            print(f"     Errors: {', '.join(errors[:2])}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Test X25519MLKEM768 variants')
    parser.add_argument('hostname', help='Hostname to test')
    parser.add_argument('--port', type=int, default=443, help='Port to test')
    
    args = parser.parse_args()
    
    results = test_x25519mlkem768_variants(args.hostname, args.port)
    print_summary(results)
    
    # Provide recommendations
    print(f"\n💡 Recommendations:")
    if results['successful_variants']:
        print("✅ Server supports X25519MLKEM768 hybrid PQ!")
        print("   This indicates post-quantum readiness with hybrid security.")
    else:
        print("❌ No X25519MLKEM768 variants worked.")
        print("   This could mean:")
        print("   • Server doesn't support this specific algorithm")
        print("   • Client tools don't have the right algorithm names")
        print("   • Server requires different naming convention")
        print("   • Network/connectivity issues")
    
    print(f"\n🔧 Next steps:")
    print("• Try with latest OQS tools: https://openquantumsafe.org/")
    print("• Check server documentation for supported PQ algorithms")
    print("• Test with other hybrid combinations (P-256+ML-KEM, etc.)")


if __name__ == "__main__":
    main()