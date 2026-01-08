# AAuth Phase 1 Testing Guide

This document outlines how to test and verify Phase 1: HTTP Message Signing Foundation.

## Overview

Phase 1 implements the core HTTP Message Signing (RFC 9421) verification infrastructure. Testing should cover:
1. **Unit Tests** - Individual component functionality
2. **Integration Tests** - End-to-end signature verification flows
3. **Manual Testing** - Using HTTP clients to verify real-world scenarios

## Test Structure

### Unit Tests Location
Create tests in: `services/src/test/java/org/keycloak/protocol/aauth/`

### Test Categories

#### 1. SignatureKeyParser Tests
**File**: `SignatureKeyParserTest.java`

**Test Cases**:
- Parse `scheme=hwk` with various parameters (kty, crv, x, n, e, kid)
- Parse `scheme=jwks` with id and kid parameters (Mode 2: Identifier + Metadata)
- Parse `scheme=jwks` with jwks and kid parameters (Mode 1: Direct JWKS URL)
- Parse `scheme=x509` with x5u parameter
- Parse `scheme=jwt` with jwt parameter
- Handle malformed headers (missing scheme, invalid parameters)
- Handle quoted vs unquoted parameter values
- Extract specific parameters (getAgentId, getKid, getX5u, getJWT)

**Example Test**:
```java
@Test
public void testParseHwkScheme() {
    String header = "hwk kty=\"OKP\" crv=\"Ed25519\" x=\"...\" kid=\"key-1\"";
    SignatureKeyParser parser = new SignatureKeyParser(header);
    assertEquals("hwk", parser.getScheme());
    assertEquals("OKP", parser.getKty());
    assertEquals("Ed25519", parser.getCrv());
    assertEquals("key-1", parser.getKid());
}
```

#### 2. SignatureBaseBuilder Tests
**File**: `SignatureBaseBuilderTest.java`

**Test Cases**:
- Build signature base with @method, @authority, @path
- Build signature base with @query component
- Build signature base with content-type and content-digest
- Build signature base with signature-key component
- Build signature base with nonce
- Handle missing required components (throw exception)
- Verify RFC 9421 canonical format (component ordering, encoding)

**Example Test**:
```java
@Test
public void testBuildSignatureBaseWithMethodAndPath() throws Exception {
    HttpRequest request = createMockRequest("POST", "/protocol/aauth/token");
    UriInfo uriInfo = createMockUriInfo("https://keycloak.example.com", "/protocol/aauth/token");
    List<String> components = Arrays.asList("@method", "@path");
    
    SignatureBaseBuilder builder = new SignatureBaseBuilder(
        request, uriInfo, components, null, 1234567890L, null
    );
    
    String base = builder.build();
    assertTrue(base.contains("\"@method\": post"));
    assertTrue(base.contains("\"@path\": /protocol/aauth/token"));
}
```

#### 3. HTTPSigVerifier Tests
**File**: `HTTPSigVerifierTest.java`

**Test Cases**:
- Verify valid signature with hwk scheme
- Verify valid signature with jwks_uri scheme
- Verify valid signature with x509 scheme
- Verify valid signature with jwt scheme
- Reject invalid signature (wrong key)
- Reject expired signature (created timestamp too old)
- Reject missing required headers (Signature-Input, Signature, Signature-Key)
- Reject malformed Signature-Input header
- Verify nonce handling (when present)

**Example Test**:
```java
@Test
public void testVerifyValidHwkSignature() throws Exception {
    // Generate key pair
    KeyPair keyPair = generateEd25519KeyPair();
    
    // Create signed request
    HttpRequest request = createSignedRequest(keyPair, "POST", "/protocol/aauth/token");
    
    // Verify signature
    HTTPSigVerifier verifier = new HTTPSigVerifier(session);
    assertTrue(verifier.verify(request, uriInfo));
}
```

#### 4. Signature Scheme Handler Tests

**HeaderWebKeySchemeTest.java**:
- Extract public key from OKP (Ed25519) parameters
- Extract public key from RSA parameters
- Handle missing kty parameter
- Handle unsupported key types
- Determine algorithm from kty/crv

**JWKSSchemeTest.java**:
- Test Mode 1: Direct JWKS URL (scheme=jwks with `jwks` and `kid` parameters)
- Test Mode 2: Identifier + Metadata (scheme=jwks with `id` and `kid` parameters)
- Fetch agent metadata from `/.well-known/aauth-agent` (Mode 2)
- Fetch JWKS from jwks_uri (Mode 2) or directly from jwks URL (Mode 1)
- Extract public key by kid
- Handle missing agent ID (Mode 2)
- Handle missing jwks parameter (Mode 1)
- Handle missing kid
- Handle invalid agent metadata
- Handle JWKS fetch failure
- Reject requests with both `jwks` and `id` parameters (mutually exclusive)
- Cache JWKS for performance

**X509SchemeTest.java**:
- Fetch certificate chain from x5u
- Extract public key from leaf certificate
- Handle missing x5u parameter
- Handle invalid certificate format
- Handle certificate fetch failure

**JWTSchemeTest.java**:
- Extract public key from agent+jwt token (cnf.jwk)
- Extract public key from auth+jwt token (cnf.jwk)
- Handle missing jwt parameter
- Handle invalid JWT format
- Handle unsupported JWT type

#### 5. Token Validator Tests

**AgentTokenValidatorTest.java**:
- Validate valid agent token
- Reject expired token
- Reject invalid signature
- Reject missing cnf.jwk claim
- Reject invalid issuer
- Verify sub claim (agent delegate identifier)
- Fetch and verify agent server JWKS

**AuthTokenValidatorTest.java**:
- Validate valid auth token
- Reject expired token
- Reject invalid signature
- Reject missing agent claim
- Reject missing cnf.jwk claim
- Verify aud claim (resource identifier)
- Fetch and verify auth server JWKS

**ResourceTokenValidatorTest.java**:
- Validate valid resource token
- Reject expired token
- Reject invalid signature
- Reject agent mismatch
- Reject agent_jkt mismatch
- Verify scope or auth_request_url presence

#### 6. Request Filter Tests

**AAuthSignatureFilterTest.java**:
- Filter applies only to `/protocol/aauth/` paths
- Filter skips `/.well-known/` endpoints
- Filter verifies signature and stores agent identity
- Filter rejects requests with invalid signatures
- Filter allows requests without Signature-Key header (for endpoints that don't require it)
- Filter sets appropriate HTTP status codes (401 for invalid signature)

## Integration Tests

### Test Setup

Create integration tests in: `testsuite/integration-arquillian/tests/base/src/test/java/org/keycloak/testsuite/protocol/aauth/`

**File**: `AAuthSignatureVerificationTest.java`

**Test Scenarios**:

1. **End-to-End Signature Verification**
   - Start Keycloak server
   - Create test agent with metadata endpoint
   - Send signed request to AAuth endpoint
   - Verify signature is validated correctly
   - Verify agent identity is extracted

2. **All Signature Schemes**
   - Test hwk scheme with Ed25519 key
   - Test jwks scheme Mode 1 (direct JWKS URL)
   - Test jwks scheme Mode 2 (identifier + metadata)
   - Test x509 scheme with certificate chain
   - Test jwt scheme with agent token

3. **Error Cases**
   - Invalid signature
   - Expired signature
   - Missing headers
   - Wrong signature scheme

## Manual Testing

### Prerequisites

1. **Start Keycloak Server**
   ```bash
   cd /path/to/keycloak
   ./mvnw clean install -DskipTests
   ./mvnw -f distribution/server-dist/pom.xml exec:java
   ```

2. **Create Test Realm**
   - Access Admin Console: http://localhost:8080/admin
   - Create realm: `aauth-test`
   - Enable AAuth protocol (once Phase 2 is complete)

### Test with curl

#### 1. Test Signature-Key Parsing

```bash
# Test hwk scheme
curl -X POST http://localhost:8080/realms/aauth-test/protocol/aauth/token \
  -H "Signature-Key: hwk kty=\"OKP\" crv=\"Ed25519\" x=\"...\" kid=\"test-key\"" \
  -H "Signature-Input: sig=(@method @path);created=1234567890" \
  -H "Signature: sig=:base64signature:"

# Test jwks scheme (Mode 2: Identifier + Metadata)
curl -X POST http://localhost:8080/realms/aauth-test/protocol/aauth/token \
  -H "Signature-Key: sig=jwks;id=\"https://agent.example.com\";kid=\"key-1\"" \
  -H "Signature-Input: sig=(@method @path);created=1234567890" \
  -H "Signature: sig=:base64signature:"

# Test jwks scheme (Mode 1: Direct JWKS URL)
curl -X POST http://localhost:8080/realms/aauth-test/protocol/aauth/token \
  -H "Signature-Key: sig=jwks;jwks=\"https://agent.example.com/jwks.json\";kid=\"key-1\"" \
  -H "Signature-Input: sig=(@method @path);created=1234567890" \
  -H "Signature: sig=:base64signature:"
```

#### 2. Test Signature Verification

**Using Python with cryptography library**:

```python
#!/usr/bin/env python3
import requests
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
import time

# Generate key pair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize public key to JWK format (x parameter)
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
x_param = base64.urlsafe_b64encode(public_key_bytes).decode('utf-8').rstrip('=')

# Build signature base string (simplified)
method = "POST"
path = "/protocol/aauth/token"
created = int(time.time())
signature_base = f'"@method": {method.lower()}\n"@path": {path}\n"@signature-params": (@method @path);created={created}'

# Sign the signature base
signature_bytes = private_key.sign(signature_base.encode('utf-8'))
signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8').rstrip('=')

# Make request
headers = {
    "Signature-Key": f'hwk kty="OKP" crv="Ed25519" x="{x_param}" kid="test-key"',
    "Signature-Input": f'sig=(@method @path);created={created}',
    "Signature": f'sig=:{signature_b64}:',
    "Content-Type": "application/json"
}

response = requests.post(
    "http://localhost:8080/realms/aauth-test/protocol/aauth/token",
    headers=headers,
    json={"grant_type": "auth", "agent": "https://agent.example.com"}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

#### 3. Test Agent Metadata Fetching

**Set up mock agent server** (using Python Flask):

```python
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/.well-known/aauth-agent')
def agent_metadata():
    return jsonify({
        "agent": "https://agent.example.com",
        "jwks_uri": "https://agent.example.com/.well-known/jwks.json",
        "redirect_uris": ["https://agent.example.com/callback"]
    })

@app.route('/.well-known/jwks.json')
def jwks():
    return jsonify({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "...",
            "kid": "key-1"
        }]
    })

if __name__ == '__main__':
    app.run(port=8000)
```

Then test with jwks scheme (Mode 2):

```bash
curl -X POST http://localhost:8080/realms/aauth-test/protocol/aauth/token \
  -H "Signature-Key: sig=jwks;id=\"http://localhost:8000\";kid=\"key-1\"" \
  -H "Signature-Input: sig=(@method @path);created=1234567890" \
  -H "Signature: sig=:base64signature:"
```

## Verification Checklist

### Phase 1 Components

- [ ] `SignatureKeyParser` correctly parses all four schemes
- [ ] `SignatureBaseBuilder` builds RFC 9421 compliant signature base strings
- [ ] `HTTPSigVerifier` verifies signatures correctly
- [ ] `HeaderWebKeyScheme` extracts public keys from header parameters
- [ ] `JWKSScheme` fetches and validates agent metadata and JWKS (both Mode 1 and Mode 2)
- [ ] `X509Scheme` fetches and parses certificate chains
- [ ] `JWTScheme` validates tokens and extracts cnf.jwk
- [ ] `AgentTokenValidator` validates agent tokens correctly
- [ ] `AuthTokenValidator` validates auth tokens correctly
- [ ] `ResourceTokenValidator` validates resource tokens correctly
- [ ] `AAuthSignatureFilter` intercepts requests and verifies signatures

### Security Checks

- [ ] Signatures are verified before processing requests
- [ ] Expired signatures are rejected (created timestamp validation)
- [ ] Invalid signatures are rejected
- [ ] Missing required headers result in appropriate errors
- [ ] Agent identity is correctly extracted and stored
- [ ] Metadata fetching validates HTTPS URLs
- [ ] Certificate chains are validated

### Performance Checks

- [ ] JWKS are cached appropriately (avoid repeated fetches)
- [ ] Metadata is cached appropriately
- [ ] Signature verification doesn't significantly impact request latency

## Running Tests

### Run All AAuth Tests (Recommended)
```bash
cd services
mvn test -Dtest="org.keycloak.protocol.aauth.signing.**"
```

This command will run all tests in the `org.keycloak.protocol.aauth.signing` package and all subpackages, including:
- `SignatureKeyParserTest`
- `SignatureBaseBuilderTest`
- `HeaderWebKeySchemeTest`
- Any future tests added to this package tree

### Run Specific Test Class
```bash
cd services
mvn test -Dtest=SignatureKeyParserTest
mvn test -Dtest=SignatureBaseBuilderTest
mvn test -Dtest=HeaderWebKeySchemeTest
```

### Integration Tests
```bash
cd testsuite/integration-arquillian
mvn test -Dtest=AAuthSignatureVerificationTest
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

