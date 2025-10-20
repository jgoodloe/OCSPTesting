# OCSP Testing Results Quick Reference Guide

## Test Result Interpretation

### Status Icons and Meanings
- ✅ **PASS**: Test completed successfully with expected results
- ❌ **FAIL**: Test failed due to unexpected behavior or errors  
- ⏭️ **SKIP**: Test was skipped due to missing prerequisites
- ⚠️ **WARN**: Warning - non-critical issue detected
- 🔍 **INFO**: Informational message with additional details

### Common Success Patterns

#### P7C Processing Success
```
[INFO] Detected P7C format CRL
[INFO] Successfully extracted CRL to /tmp/crl_abc123.crl
[OK] CRL parsing successful
```

#### OCSP Response Success
```
[OK] Signature verification: PASS
[OK] Response Validity Interval: VALID
[OK] Certificate Status: GOOD
[OK] Certificate validation PASSED
```

#### CRL Validation Success
```
[OK] CRL Signature Valid
[OK] CRL timestamps valid
[OK] CRL downloaded and parsed successfully
```

### Common Failure Patterns

#### Signature Verification Failure
```
[ERROR] Signature verification: FAIL
[ERROR] CRL signature invalid
```
**Action**: Check issuer certificate, verify certificate chain

#### Timestamp Issues
```
[ERROR] Response Validity Interval: INVALID
[WARN] thisUpdate is too old (49.0 hours > 24 hours)
```
**Action**: Check system clock, verify OCSP server operational

#### Cryptographic Issues
```
[ERROR] Cryptographic downgrade attack detected
[WARN] SHA-1 algorithm detected (deprecated)
```
**Action**: Reject weak algorithms, use strong cryptographic preferences

#### HTTP POST Issues
```
[ERROR] HTTP POST support validation FAILED
[WARN] Server supports GET but not POST
```
**Action**: Use GET for small requests, implement POST support

### Security Assessment Levels

#### SECURE
- Strong cryptographic algorithms supported
- No downgrade attacks detected
- Proper signature verification
- Valid response intervals

#### ACCEPTABLE  
- Minimum recommended algorithms supported
- Minor security warnings
- Generally compliant behavior

#### WEAK
- Only weak algorithms supported
- Security warnings present
- Compliance issues detected

#### CRITICAL
- No supported algorithms found
- Major security vulnerabilities
- Non-compliant behavior

### Performance Indicators

#### Response Time Categories
- **<100ms**: Excellent performance
- **100-500ms**: Good performance  
- **500ms-2s**: Acceptable performance
- **>2s**: Poor performance

#### Success Rate Categories
- **≥95%**: Excellent reliability
- **90-95%**: Good reliability
- **80-90%**: Acceptable reliability
- **<80%**: Poor reliability

### Test Categories Quick Reference

#### Protocol Tests
- HTTP GET/POST transport
- DER encoding validation
- Basic response fields

#### Status Tests  
- Certificate status validation
- Timestamp field validation
- Response structure validation

#### Security Tests
- Malformed request handling
- Signature algorithm validation
- Cryptographic preference negotiation
- Downgrade attack detection

#### CRL Tests
- CRL distribution point extraction
- CRL download and parsing
- CRL signature verification
- CRL timestamp validation
- CRL vs OCSP consistency

### Error Code Reference

#### HTTP Status Codes
- **200**: Success
- **400**: Bad Request (malformed data)
- **413**: Payload Too Large (oversized request)
- **500**: Internal Server Error

#### OCSP Response Status
- **successful (0x0)**: Valid response
- **malformedRequest (1)**: Request format error
- **internalError (2)**: Server internal error
- **tryLater (3)**: Temporary unavailability
- **sigRequired (4)**: Signed request required
- **unauthorized (5)**: Request not authorized

### Quick Troubleshooting

#### Connection Issues
```
[ERROR] Connection refused
[ERROR] Network timeout
```
**Solution**: Check network connectivity, verify OCSP server URL

#### Certificate Issues
```
[ERROR] Could not read certificate file
[ERROR] Certificate parsing failed
```
**Solution**: Verify certificate file exists and is in PEM format

#### OpenSSL Issues
```
[ERROR] OpenSSL command failed
[ERROR] Unable to load certificate
```
**Solution**: Check OpenSSL installation, verify certificate format

#### File Processing Issues
```
[ERROR] CRL parsing failed completely
[ERROR] Could not process P7C file
```
**Solution**: Check file format, try alternative processing methods

### Best Practices Summary

1. **Always verify signatures** before trusting results
2. **Check response validity intervals** for freshness
3. **Use strong cryptographic algorithms** only
4. **Validate certificate status explicitly** (GOOD only)
5. **Test both GET and POST methods** for completeness
6. **Monitor performance metrics** for optimization
7. **Review security warnings** for potential issues

### Configuration Tips

- Enable `test_non_issued_certificates` for RFC 6960 compliance testing
- Enable `test_cryptographic_preferences` for security validation
- Set `max_age_hours` based on your security requirements
- Configure `preferred_algorithms` for your security policy

This quick reference guide helps you quickly interpret test results and take appropriate action based on the system's comprehensive security validations.
