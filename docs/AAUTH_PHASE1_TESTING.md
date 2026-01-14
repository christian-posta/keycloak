# AAuth Phase 1 Testing Guide

This document outlines how to test and verify Phase 1: HTTP Message Signing Foundation.

## Overview

Phase 1 implements the core HTTP Message Signing (RFC 9421) verification infrastructure. Testing should cover:
1. **Unit Tests** - Individual component functionality
2. **Manual Testing** - Using HTTP clients to verify real-world scenarios

## Manual Testing

For manual end-to-end testing of the AAuth protocol (including HTTP signature verification), see:

- **[Phase 4 Token Exchange Manual Testing Guide](AAUTH_PHASE4_EXCHANGE_MANUAL_TESTING.md)** - Complete testing instructions using the Python test client and automated test script


## Running Tests

### Prerequisites

Before running tests, ensure the services module is compiled. If you've made source code changes, you **must** do a clean compile first to avoid "Unresolved compilation problems" errors:

```bash
cd services
../mvnw clean test-compile -q
```

### Run All AAuth Signing Tests (Recommended)

```bash
cd services
../mvnw clean test -Dtest="org.keycloak.protocol.aauth.signing.**"
```

This command will run all tests in the `org.keycloak.protocol.aauth.signing` package and all subpackages (74 tests total):
- `SignatureKeyParserTest` (15 tests)
- `SignatureBaseBuilderTest` (18 tests)
- `HTTPSigVerifierTest` (8 tests)
- `HeaderWebKeySchemeTest` (9 tests)
- `JWKSSchemeTest` (14 tests)
- `JWTSchemeTest` (10 tests)

**Expected output:**
```
Tests run: 74, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

### Run Specific Test Class

```bash
cd services
../mvnw clean test -Dtest=SignatureKeyParserTest
../mvnw test -Dtest=SignatureBaseBuilderTest      # No clean needed after first run
../mvnw test -Dtest=HeaderWebKeySchemeTest
../mvnw test -Dtest=HTTPSigVerifierTest
../mvnw test -Dtest=JWKSSchemeTest
../mvnw test -Dtest=JWTSchemeTest
```

### Troubleshooting Test Failures

**"Unresolved compilation problems" errors:**

If you see errors like:
```
SignatureKeyParser cannot be resolved to a type
JWKSScheme cannot be resolved to a type
```

This means the test classes have stale `.class` files. Fix by running `clean` before tests:
```bash
../mvnw clean test -Dtest="org.keycloak.protocol.aauth.signing.**"
```

## Debugging Tips

1. **Enable Debug Logging**
   Add to `standalone/configuration/logging.properties`:
   ```
   logger.org.keycloak.protocol.aauth.level=DEBUG
   ```

2. **Check Filter Execution**
   Add logging in `AAuthSignatureFilter` to see when it's invoked

3. **Verify Signature Base String**
   Log the signature base string in `SignatureBaseBuilder` to verify RFC 9421 compliance

4. **Test Individual Components**
   Create standalone test classes to test parsers and builders in isolation

## Next Steps

After Phase 1 is verified:
- Proceed to Phase 2: Core Protocol Endpoints
- Add more comprehensive error handling
- Add performance optimizations (caching, connection pooling)
- Add metrics/monitoring for signature verification