# Post-Quantum Cryptography Testing Guide

## Current Limitations

Our TLS scanner has important limitations when it comes to detecting post-quantum (PQ) cryptography:

### ❌ What We Cannot Detect
- **Hybrid PQ key exchange** - Requires a PQ-capable client
- **Server's PQ capabilities** - Only visible to PQ-enabled clients
- **Actual PQ algorithms** used during handshake
- **PQ certificate signatures** - Need specialized certificate analysis

### ✅ What We Can Detect
- **Explicit PQ cipher suite names** (rare in production)
- **TLS 1.3 support** (prerequisite for most PQ implementations)
- **Modern cipher suites** (compatible with hybrid PQ)
- **Known PQ-experimenting providers** (Cloudflare, Google, etc.)

## Why This Happens

Most real-world PQ deployment uses **hybrid cryptography**:
1. Server supports both classical and PQ algorithms
2. Server only offers PQ to PQ-capable clients
3. Our Python client uses standard `ssl` library (no PQ support)
4. Server responds with classical algorithms only

## How to Actually Test PQ Support

### Method 1: Use PQ-Enabled curl

```bash
# Build curl with PQ-enabled OpenSSL
git clone https://github.com/open-quantum-safe/openssl.git
cd openssl
./Configure && make && make install

# Build curl with PQ OpenSSL
git clone https://github.com/curl/curl.git
cd curl
./configure --with-openssl=/path/to/pq-openssl
make && make install

# Test with PQ groups
curl -v --curves kyber512 https://example.com
curl -v --curves x25519_kyber512 https://example.com
```

### Method 2: Use OpenSSL s_client with PQ

```bash
# With PQ-enabled OpenSSL
openssl s_client -connect example.com:443 -groups kyber512
openssl s_client -connect example.com:443 -groups x25519_kyber512
```

### Method 3: Use Specialized Tools

#### OQS-OpenSSL Test Client
```bash
# Clone and build OQS-OpenSSL
git clone https://github.com/open-quantum-safe/openssl.git oqs-openssl
cd oqs-openssl
./Configure && make

# Test PQ key exchange
./apps/openssl s_client -connect example.com:443 -curves kyber512
```

#### Wireshark Analysis
1. Install Wireshark with TLS 1.3 support
2. Use PQ-capable client to connect
3. Analyze handshake for PQ key exchange extensions

### Method 4: Check Provider Documentation

#### Cloudflare
- Check [Cloudflare's PQ documentation](https://blog.cloudflare.com/post-quantum-cryptography/)
- Look for announcements about PQ support
- Test with their experimental endpoints

#### Google
- Check Google's PQ experiments
- Test with Chrome's PQ flags enabled

## Known PQ-Supporting Services

### Experimental/Test Servers
- `pq.googleapis.com` (Google's PQ test server)
- `tls13-pq.cloudflareresearch.com` (Cloudflare research)
- `test.openquantumsafe.org` (OQS test server)

### Production Services with Hybrid PQ
- Cloudflare-protected sites (hybrid mode)
- Google services (experimental)
- Some AWS CloudFront distributions

## Interpreting Our Scanner Results

When our scanner shows:
```
Post-Quantum Assessment:
  Has PQ Ciphers: False
  Overall Ready: False
  Limitations:
    • Client does not support PQ key exchange
    • Only cipher suite names are analyzed
```

This means:
- ✅ We successfully connected with TLS 1.3
- ✅ Server uses modern, secure cipher suites
- ❓ Server **might** support PQ with PQ-capable clients
- ❌ We cannot confirm PQ support with our current client

## Future Improvements

To improve PQ detection, we would need:

1. **PQ-enabled OpenSSL binding** for Python
2. **Custom TLS implementation** with PQ support
3. **External tool integration** (curl, openssl s_client)
4. **Certificate analysis** for PQ signatures
5. **Server fingerprinting** based on known PQ deployments

## Recommended Testing Workflow

1. **Use our scanner** for basic TLS assessment
2. **Check for TLS 1.3 + modern ciphers** (PQ prerequisites)
3. **Identify potential PQ providers** (Cloudflare, Google, etc.)
4. **Use specialized PQ tools** for definitive testing
5. **Monitor industry announcements** for PQ deployment news

## Example: Testing a Domain

```bash
# 1. Our scanner (basic assessment)
python scripts/scan_tls.py example.com

# 2. Check certificate issuer
openssl s_client -connect example.com:443 -servername example.com < /dev/null | openssl x509 -text

# 3. Test with PQ-enabled client (if available)
curl -v --curves kyber512 https://example.com

# 4. Check provider's PQ status
# Visit provider dashboard or documentation
```

## Conclusion

Our TLS scanner provides valuable baseline security assessment and identifies servers that are **potentially** PQ-ready based on:
- Modern TLS support
- Secure cipher suites  
- Known PQ-experimenting providers

For definitive PQ testing, specialized tools with PQ-enabled TLS stacks are required.