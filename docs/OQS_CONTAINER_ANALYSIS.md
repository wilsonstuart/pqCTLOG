# OQS Docker Container Analysis

## Container Versions (as of testing)

### openquantumsafe/curl
- **curl**: 8.14.0 (x86_64-pc-linux-musl) 
- **OpenSSL**: 3.4.0
- **PQ Support**: Limited - `--curves` parameter doesn't seem to work properly
- **Status**: ❌ Not suitable for PQ curve testing

### openquantumsafe/oqs-ossl3  
- **OpenSSL**: 3.4.0 22 Oct 2024
- **liboqs**: Present (version detection needs improvement)
- **PQ Support**: ✅ Excellent - supports multiple PQ algorithms
- **Status**: ✅ Suitable for PQ group testing

## Supported Algorithms

### ✅ Working with OpenSSL Container
- `kyber512` - Kyber-512 key encapsulation
- `kyber768` - Kyber-768 key encapsulation  
- `mlkem768` - **ML-KEM-768 (NIST standardized)**
- `x25519mlkem768` - **X25519+ML-KEM-768 hybrid (your target algorithm)**

### ❌ Not Working with curl Container
- All PQ curves fail with current container
- `--curves` parameter appears non-functional
- May need different container version or configuration

## Key Findings

### X25519MLKEM768 Support
🎯 **The OpenSSL container DOES support `x25519mlkem768`!**

This means:
- The algorithm is available in the OQS ecosystem
- Servers supporting this algorithm can be tested
- The naming convention `x25519mlkem768` (lowercase) works

### Testing Recommendations

1. **Use OpenSSL container** for PQ testing:
   ```bash
   docker run --rm openquantumsafe/oqs-ossl3 openssl s_client -connect regdata.fca.org.uk:443 -groups x25519mlkem768
   ```

2. **Avoid curl container** for now - PQ curves not working

3. **Test with multiple naming variants**:
   - `x25519mlkem768` (confirmed working)
   - `X25519MLKEM768` (may work)
   - `mlkem768` (confirmed working)

## Next Steps

### For Testing X25519MLKEM768
```bash
# Test if regdata.fca.org.uk supports X25519MLKEM768
python scripts/docker_pq_test.py regdata.fca.org.uk

# The OpenSSL test should now work for x25519mlkem768
```

### For Development
- Focus on OpenSSL-based testing
- Update curl container or find alternative
- Add more algorithm variants to test suite

## Container Update Recommendations

1. **Check for newer curl container** with working PQ support
2. **Verify liboqs version** in containers
3. **Test with latest OQS releases**
4. **Consider building custom containers** if needed

## Algorithm Priority

Based on testing results, prioritize:
1. `x25519mlkem768` - Hybrid, NIST standard ✅
2. `mlkem768` - Pure NIST standard ✅  
3. `kyber768` - Legacy but working ✅
4. `kyber512` - Smaller key size ✅