# AAuth Phase 2 Manual Testing Guide

This document provides step-by-step instructions for manually testing the AAuth direct grant flow (`request_type=auth`) once Keycloak is built and running.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)
4. [Test Scenarios](#test-scenarios)
5. [Creating Signed Requests](#creating-signed-requests)
6. [Validating Responses](#validating-responses)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Build and Start Keycloak

```bash
# Build Keycloak (first time: ~10-30 minutes)
cd /path/to/keycloak

# Build this first
./mvnw -pl services clean install -DskipTests

# Rebuild services + server (without clean to keep jar)
./mvnw -pl services,quarkus/server,quarkus/deployment,quarkus/dist -am install -DskipTests -DskipProtoLock=true

# Full rebuild (takes longer)
./mvnw -pl core,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true

# May need to do this (keep in back pocket):
# The Infinispan marshaller classes are generated during the model/infinispan build. Rebuilding only services doesn't regenerate them, so the server JAR has stale marshallers that reference classes that don't exist or have changed.
./mvnw -pl model/infinispan clean install -DskipTests -Dmaven.test.skip=true

# Alternative: Full build (if you want everything)
# ./mvnw clean install -DskipTests -DskipProtoLock=true

# Start Keycloak with bootstrap admin (creates admin user automatically)
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \
  --bootstrap-admin-username=admin \
  --bootstrap-admin-password=admin
```

**Note**: If you start Keycloak without bootstrap flags, you'll need to create the admin user via the web UI on first startup (visit http://localhost:8080).

**Verify**: Open `http://localhost:8080` - you should see the Keycloak welcome page.

### 2. Create Test Realm

**Option A: Command Line (Fastest)**
```bash
./scripts/create_realm.sh
```

**Option B: Admin Console**
1. Open `http://localhost:8080/admin` (username: `admin`, password: `admin`)
2. Click "Create Realm" → Name: `aauth-test` → "Create"

### 3. Test AAuth Endpoints

**Option A: Use the Python test client (easiest)**

```bash
# Install dependencies
pip install cryptography requests

# Fetch metadata
python scripts/aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --metadata

# Request token with scope
python scripts/aauth_test_client.py --base-url http://localhost:8080 --realm aauth-test --scope "data.read data.write"

# Resource Token from Mock Server:
./scripts/test_resource_token_flow.sh
```

**Option B: Use curl** (see [Test Scenarios](#test-scenarios) for detailed steps)

The Python script handles:
- ✅ Key pair generation
- ✅ HTTP Message Signature creation
- ✅ Request formatting
- ✅ Response parsing

For detailed manual testing steps, see the [Test Scenarios](#test-scenarios) section below.

## Prerequisites

### Required Tools

1. **Keycloak Server** - Built and running
2. **curl** or **HTTPie** - For making HTTP requests
3. **Python 3** (optional) - For generating signed requests programmatically
4. **jq** (optional) - For pretty-printing JSON responses
5. **OpenSSL** or **Java keytool** - For generating Ed25519 keys

### Keycloak Setup

#### Step 1: Build Keycloak

First, ensure you have **JDK 17** or **JDK 21** installed:

```bash
java -version  # Should show JDK 17 or 21
```

Build Keycloak from source (this includes the AAuth implementation):

**Option A: Full Build (Recommended if you have time)**

```bash
# Navigate to Keycloak root directory
cd /path/to/keycloak

# Build Keycloak (skip tests for faster build)
./mvnw clean install -DskipTests
```

**Option B: Build Only Server (Faster, avoids some compatibility checks)**

```bash
# Build only the server modules (faster, avoids Infinispan proto checks)
./mvnw -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install
```

**Option C: Skip Proto Schema Compatibility Check**

If you encounter protobuf schema compatibility errors (common issue), skip the check:

```bash
# Build with proto compatibility check disabled
./mvnw clean install -DskipTests -DskipProtoLock=true
```

**Option D: Build Only Server (Recommended - Skips Test Suite)**

Skip the test suite entirely (which has compilation issues) and build only what's needed to run Keycloak:

```bash
# Build core, services, and server (skips test suite)
./mvnw -pl core,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true
```

**Note**: This excludes the test suite which has known compilation issues. Perfect for manual testing!

**Note**: 
- The first build can take 10-30 minutes depending on your machine. Subsequent builds are faster.
- If you see protobuf/protolock errors, use Option C or Option D.
- For AAuth testing, Option D is usually sufficient.

#### Step 2: Start Keycloak Server

You have two options for starting Keycloak:

**Option A: Run from JAR (Recommended for testing)**

```bash
# Start Keycloak in development mode with bootstrap admin user
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \
  --bootstrap-admin-username=admin \
  --bootstrap-admin-password=admin
```

**Note**: The `--bootstrap-admin-username` and `--bootstrap-admin-password` flags create an admin user automatically. Without these, you'll need to create the admin user via the web UI on first startup.

**Option B: Run in Quarkus Dev Mode (Recommended for development)**

This enables hot-reload when you make code changes:

```bash
# From the Keycloak root directory
./mvnw -f quarkus/server/pom.xml compile quarkus:dev \
  -Dquarkus.args="start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin"
```

**Note**: The bootstrap flags create an admin user automatically. Without them, you'll need to create the admin user via the web UI on first startup.

**Expected Output**:
```
__  ____  __  _____   ___  __ ____  ______ 
 --/ __ \/ / / / _ | / _ \/ //_/ / / / __/ 
 -/ /_/ / /_/ / __ |/ , _/ ,< / /_/ /\ \   
--\___\_\____/_/ |_/_/|_/_/|_|\____/___/   
2024-01-08 14:00:00,000 INFO  [org.keycloak] (main) KC-SERVICES0001: Initializing Keycloak Server
...
2024-01-08 14:00:15,000 INFO  [org.keycloak] (main) KC-SERVICES0050: Keycloak 26.2.5 started in 15.000s
```

**Verify Keycloak is Running**:
- Open `http://localhost:8080` in your browser
- You should see the Keycloak welcome page
- The server is ready when you see "Keycloak started" in the logs

**To Stop Keycloak**: Press `Ctrl+C` in the terminal

#### Step 3: Create Test Realm

You have two options to create the realm:

**Option A: Using Command Line (Faster)**

Use the provided script:

```bash
# Create realm 'aauth-test' (default)
./scripts/create_realm.sh

# Or specify custom parameters
./scripts/create_realm.sh http://localhost:8080 aauth-test admin admin
```

**Option B: Using Admin Console (Manual)**

1. **Access Admin Console**:
   - Open `http://localhost:8080/admin` in your browser
   - Default credentials (if using `start-dev`):
     - Username: `admin`
     - Password: `admin`

2. **Create Realm**:
   - Click the dropdown in the top-left (shows "master")
   - Click "Create Realm"
   - Enter realm name: `aauth-test`
   - Click "Create"
   - The realm will be enabled by default

3. **Verify Realm**:
   - You should see `aauth-test` in the realm dropdown
   - The realm is now active

**Verify Realm Created**:

```bash
# Test that realm exists
curl http://localhost:8080/realms/aauth-test/.well-known/openid-configuration | jq .issuer
# Should output: "http://localhost:8080/realms/aauth-test"
```

#### Step 4: Verify AAuth Protocol is Available

The AAuth protocol endpoints should be automatically available. Test with:

```bash
# Test metadata endpoint
curl http://localhost:8080/realms/aauth-test/.well-known/aauth-issuer | jq
```

**Expected Response**:
```json
{
  "issuer": "http://localhost:8080/realms/aauth-test",
  "agent_token_endpoint": "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token",
  ...
}
```

If you get a 404 or error, check:
- Keycloak server logs for errors
- Ensure the AAuth code was compiled (check `services/target/classes/org/keycloak/protocol/aauth/`)
- Restart Keycloak if you just added the AAuth code

## Setup

### Generate Ed25519 Key Pair

You'll need an Ed25519 key pair for signing requests. Here are options:

#### Option 1: Using Java (Recommended)

Create a simple Java program to generate keys:

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class GenerateKeyPair {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = kpg.generateKeyPair();
        
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        
        System.out.println("Public Key (Base64): " + Base64.getEncoder().encodeToString(publicKeyBytes));
        System.out.println("Private Key (Base64): " + Base64.getEncoder().encodeToString(privateKeyBytes));
    }
}
```

#### Option 2: Using Python

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize keys
private_bytes = private_key.private_bytes_raw()
public_bytes = public_key.public_bytes_raw()

print(f"Private Key: {base64.urlsafe_b64encode(private_bytes).decode()}")
print(f"Public Key: {base64.urlsafe_b64encode(public_bytes).decode()}")
```

#### Option 3: Using OpenSSL (if available)

```bash
openssl genpkey -algorithm Ed25519 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

### Store Key Information

For testing, you'll need:
- **Agent ID**: `https://agent.example.com` (or your own HTTPS URL)
- **Public Key**: The Ed25519 public key (as JWK `x` parameter)
- **Private Key**: The Ed25519 private key (for signing)

## Test Scenarios

### Test 1: Well-Known Metadata Discovery

**Purpose**: Verify that Keycloak exposes AAuth issuer metadata correctly.

**Request**:
```bash
curl -X GET \
  "http://localhost:8080/realms/aauth-test/.well-known/aauth-issuer" \
  -H "Accept: application/json" | jq
```

**Expected Response** (200 OK):
```json
{
  "issuer": "http://localhost:8080/realms/aauth-test",
  "jwks_uri": "http://localhost:8080/realms/aauth-test/protocol/aauth/certs",
  "agent_token_endpoint": "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token",
  "agent_auth_endpoint": "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth",
  "agent_signing_algs_supported": ["Ed25519", "ES256", "RS256"],
  "request_types_supported": ["auth"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

**Validation**:
- ✅ Status code is 200
- ✅ `issuer` matches the realm URL
- ✅ `agent_token_endpoint` is present
- ✅ `request_types_supported` includes `"auth"`
- ✅ `agent_signing_algs_supported` includes `"Ed25519"`

---

### Test 2: Direct Grant with Scope (Agent as Resource)

**Purpose**: Request an auth token using `scope` parameter, where the agent acts as its own resource.

**Prerequisites**: 
- Ed25519 key pair generated
- Agent ID: `https://agent.example.com`

**Request**: You'll need to create a signed HTTP request. See [Creating Signed Requests](#creating-signed-requests) section below.

**Manual Steps**:

1. **Generate the signature components** (see Python script below)
2. **Make the signed request**:
```bash
curl -X POST \
  "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token" \
  -H "Host: localhost:8080" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"YOUR_X_VALUE\";kid=\"YOUR_KID\"" \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\");created=TIMESTAMP" \
  -H "Signature: sig=:YOUR_SIGNATURE:" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "request_type=auth&scope=data.read+data.write"
```

**Expected Response** (200 OK):
```json
{
  "auth_token": "eyJ0eXAiOiJhdXRoK2p3dCIsImtpZCI6IktleWNsb2FrU2lnbmluZ0tleSJ9...",
  "expires_in": 300,
  "token_type": "AAuth"
}
```

**Validation**:
- ✅ Status code is 200
- ✅ `auth_token` is present and is a valid JWT
- ✅ `token_type` is `"AAuth"`
- ✅ Decode the JWT and verify:
  - `typ` header is `"auth+jwt"`
  - `iss` matches the realm issuer
  - `aud` matches the agent ID (since agent is the resource)
  - `agent` claim matches your agent ID
  - `scope` claim matches `"data.read data.write"`
  - `cnf.jwk` is present and contains the agent's public key

---

### Test 3: Direct Grant with Resource Token

**Purpose**: Request an auth token using a `resource_token` parameter, where a resource authorizes the agent.

**Prerequisites**:
- Ed25519 key pair for agent
- A resource token (signed by the resource)
- Mock resource server running (for Keycloak to fetch resource metadata and JWKS)

**Note**: For manual testing, we'll use a mock resource server. In production, this would be a real resource server.

#### Step 1: Start the Mock Resource Server

In a **separate terminal**, start the mock resource server:

```bash
# Start mock resource server (saves key to resource_key.pem)
python scripts/mock_resource_server.py \
  --port 9000 \
  --resource-url http://localhost:9000 \
  --key-file resource_key.pem

# The server will display:
# Mock Resource Server
# Resource URL: http://localhost:9000
# Listening on: http://0.0.0.0:9000
# 
# Endpoints:
#   GET http://localhost:9000/.well-known/aauth-resource
#   GET http://localhost:9000/jwks.json
```

**Verify** the resource server is running:
```bash
curl http://localhost:9000/.well-known/aauth-resource | jq
```

You should see resource metadata with `jwks_uri` pointing to `/jwks.json`.

#### Step 2: Export Agent Public Key

The resource token needs to reference the agent's public key. Export it:

```bash
# Create a Python script to export the key (or modify aauth_test_client.py)
python3 <<EOF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import sys

# Generate or load agent key (same as test client uses)
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Save public key
with open('agent_public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Save private key for test client
with open('agent_private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("Agent keys saved to agent_public_key.pem and agent_private_key.pem")
EOF
```

#### Step 3: Generate Resource Token

Generate a resource token signed by the resource:

```bash
python scripts/generate_resource_token.py \
  --resource-url http://localhost:9000 \
  --agent-id https://agent.example.com \
  --agent-public-key-file agent_public_key.pem \
  --auth-server-id http://localhost:8080/realms/aauth-test \
  --scope "data.read data.write" \
  --key-file resource_key.pem
```

This will output a JWT token. **Save it** to a variable:

```bash
RESOURCE_TOKEN=$(python scripts/generate_resource_token.py \
  --resource-url http://localhost:9000 \
  --agent-id https://agent.example.com \
  --agent-public-key-file agent_public_key.pem \
  --auth-server-id http://localhost:8080/realms/aauth-test \
  --scope "data.read data.write" \
  --key-file resource_key.pem)

echo "Resource token: $RESOURCE_TOKEN"
```

#### Step 4: Request Auth Token with Resource Token

Now use the Python test client with the resource token:

```bash
# Option A: Use Python test client (recommended)
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --resource-token "$RESOURCE_TOKEN" \
  --agent-id https://agent.example.com
```

**Note**: The Python test client will generate a new agent key pair each time. To use the same agent key that matches the resource token, you'll need to modify the script to load `agent_private_key.pem`, or create a wrapper script.

**Alternative: Manual curl** (requires generating signature manually - see [Creating Signed Requests](#creating-signed-requests))

**Request**:
```bash
curl -X POST \
  "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token" \
  -H "Host: localhost:8080" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"YOUR_X_VALUE\";kid=\"YOUR_KID\"" \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\");created=TIMESTAMP" \
  -H "Signature: sig=:YOUR_SIGNATURE:" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "request_type=auth&resource_token=YOUR_RESOURCE_TOKEN"
```

**Expected Response** (200 OK):
```json
{
  "auth_token": "eyJ0eXAiOiJhdXRoK2p3dCIsImtpZCI6IktleWNsb2FrU2lnbmluZ0tleSJ9...",
  "expires_in": 300,
  "token_type": "AAuth"
}
```

**Validation**:
- ✅ Status code is 200
- ✅ `auth_token` is present
- ✅ Decode the JWT and verify:
  - `aud` matches the resource ID from the resource token
  - `agent` claim matches your agent ID
  - `cnf.jwk` contains the agent's public key

---

### Test 4: Error Case - Missing Signature-Key Header

**Purpose**: Verify that requests without HTTP Message Signatures are rejected.

**Request**:
```bash
curl -X POST \
  "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "request_type=auth&scope=data.read"
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "invalid_request",
  "error_description": "HTTP Message Signature required"
}
```

**Validation**:
- ✅ Status code is 401
- ✅ Error response indicates missing signature

---

### Test 5: Error Case - Invalid Signature

**Purpose**: Verify that requests with invalid signatures are rejected.

**Request**:
```bash
curl -X POST \
  "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token" \
  -H "Host: localhost:8080" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"YOUR_X_VALUE\";kid=\"YOUR_KID\"" \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\");created=TIMESTAMP" \
  -H "Signature: sig=:invalid_signature_here:" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "request_type=auth&scope=data.read"
```

**Expected Response** (401 Unauthorized):
```json
{
  "error": "invalid_request",
  "error_description": "Invalid HTTP Message Signature"
}
```

**Validation**:
- ✅ Status code is 401
- ✅ Error response indicates invalid signature

---

### Test 6: Error Case - Missing Parameters

**Purpose**: Verify that requests missing both `scope` and `resource_token` are rejected.

**Request**:
```bash
curl -X POST \
  "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token" \
  -H "Host: localhost:8080" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"YOUR_X_VALUE\";kid=\"YOUR_KID\"" \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\");created=TIMESTAMP" \
  -H "Signature: sig=:YOUR_SIGNATURE:" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "request_type=auth"
```

**Expected Response** (400 Bad Request):
```json
{
  "error": "invalid_request",
  "error_description": "Either 'scope' or 'resource_token' must be provided"
}
```

**Validation**:
- ✅ Status code is 400
- ✅ Error response indicates missing parameters

---

### Test 7: Default request_type

**Purpose**: Verify that omitting `request_type` defaults to `"auth"`.

**Request**:
```bash
curl -X POST \
  "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token" \
  -H "Host: localhost:8080" \
  -H "Signature-Key: sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"YOUR_X_VALUE\";kid=\"YOUR_KID\"" \
  -H "Signature-Input: sig=(\"@method\" \"@authority\" \"@path\");created=TIMESTAMP" \
  -H "Signature: sig=:YOUR_SIGNATURE:" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "scope=data.read"
```

**Expected Response** (200 OK):
```json
{
  "auth_token": "eyJ0eXAiOiJhdXRoK2p3dCIsImtpZCI6IktleWNsb2FrU2lnbmluZ0tleSJ9...",
  "expires_in": 300,
  "token_type": "AAuth"
}
```

**Validation**:
- ✅ Status code is 200
- ✅ Token is issued successfully (defaults to `request_type=auth`)

---

## Creating Signed Requests

Creating HTTP Message Signatures manually is complex. Here are tools to help:

### Python Script for Generating Signed Requests

Save this as `aauth_client.py`:

```python
#!/usr/bin/env python3
"""
AAuth Client - Generate signed HTTP requests for AAuth protocol testing
"""
import sys
import json
import base64
import time
import urllib.parse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import requests

class AAuthClient:
    def __init__(self, private_key_pem=None, agent_id="https://agent.example.com"):
        """
        Initialize AAuth client.
        
        Args:
            private_key_pem: PEM-encoded private key (optional, generates new if not provided)
            agent_id: Agent identifier (HTTPS URL)
        """
        if private_key_pem:
            # Load from PEM
            self.private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
        else:
            # Generate new key pair
            self.private_key = Ed25519PrivateKey.generate()
        
        self.public_key = self.private_key.public_key()
        self.agent_id = agent_id
        
        # Extract JWK parameters
        self.jwk_x = self._get_jwk_x()
        self.kid = self._get_kid()
    
    def _get_jwk_x(self):
        """Extract 'x' parameter for JWK (Ed25519 public key)"""
        public_bytes = self.public_key.public_bytes_raw()
        return base64.urlsafe_b64encode(public_bytes).decode().rstrip('=')
    
    def _get_kid(self):
        """Generate key ID (simplified - use thumbprint in production)"""
        return base64.urlsafe_b64encode(self.jwk_x.encode()[:16]).decode().rstrip('=')
    
    def _build_signature_base(self, method, authority, path, created):
        """
        Build signature base string per RFC 9421.
        This is a simplified version - full implementation would handle all components.
        """
        # For basic testing: @method, @authority, @path
        signature_base = f'"@method": {method.lower()}\n'
        signature_base += f'"@authority": {authority.lower()}\n'
        signature_base += f'"@path": {path}\n'
        signature_base += f'"@signature-params": ("@method" "@authority" "@path");created={created}'
        return signature_base.encode('utf-8')
    
    def _sign(self, data):
        """Sign data with Ed25519 private key"""
        return self.private_key.sign(data)
    
    def create_signed_request(self, method, url, body=None):
        """
        Create a signed HTTP request.
        
        Returns:
            dict: Headers dictionary with Signature-Key, Signature-Input, and Signature
        """
        parsed = urllib.parse.urlparse(url)
        authority = parsed.netloc
        path = parsed.path
        if parsed.query:
            path += '?' + parsed.query
        
        created = int(time.time())
        
        # Build signature base
        signature_base = self._build_signature_base(method, authority, path, created)
        
        # Sign
        signature_bytes = self._sign(signature_base)
        signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
        
        # Create headers
        signature_key = f'sig=hwk;kty="OKP";crv="Ed25519";x="{self.jwk_x}";kid="{self.kid}"'
        signature_input = f'sig=("@method" "@authority" "@path");created={created}'
        signature = f'sig=:{signature_b64}:'
        
        headers = {
            'Host': authority,
            'Signature-Key': signature_key,
            'Signature-Input': signature_input,
            'Signature': signature
        }
        
        if body:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        return headers
    
    def request_token(self, base_url, realm, scope=None, resource_token=None):
        """
        Request an AAuth token.
        
        Args:
            base_url: Keycloak base URL (e.g., http://localhost:8080)
            realm: Realm name
            scope: Scope string (for agent-as-resource)
            resource_token: Resource token (for resource authorization)
        
        Returns:
            dict: Response JSON
        """
        token_url = f"{base_url}/realms/{realm}/protocol/aauth/agent/token"
        
        # Build form data
        form_data = {'request_type': 'auth'}
        if scope:
            form_data['scope'] = scope
        elif resource_token:
            form_data['resource_token'] = resource_token
        else:
            raise ValueError("Either 'scope' or 'resource_token' must be provided")
        
        # Create signed request
        headers = self.create_signed_request('POST', token_url, body=True)
        
        # Make request
        response = requests.post(token_url, headers=headers, data=form_data)
        
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
        }


def main():
    """Example usage"""
    if len(sys.argv) < 3:
        print("Usage: python aauth_client.py <base_url> <realm> [scope|resource_token]")
        print("Example: python aauth_client.py http://localhost:8080 aauth-test 'data.read data.write'")
        sys.exit(1)
    
    base_url = sys.argv[1]
    realm = sys.argv[2]
    scope_or_token = sys.argv[3] if len(sys.argv) > 3 else None
    
    client = AAuthClient()
    
    print(f"Agent ID: {client.agent_id}")
    print(f"Public Key (x): {client.jwk_x}")
    print(f"Key ID: {client.kid}")
    print()
    
    # Determine if scope or resource_token
    if scope_or_token and scope_or_token.startswith('eyJ'):
        # Looks like a JWT token
        result = client.request_token(base_url, realm, resource_token=scope_or_token)
    else:
        result = client.request_token(base_url, realm, scope=scope_or_token or 'data.read')
    
    print(f"Status: {result['status_code']}")
    print(f"Response: {json.dumps(result['body'], indent=2)}")


if __name__ == '__main__':
    main()
```

**Usage**:
```bash
# Install dependencies
pip install cryptography requests

# Request token with scope
python aauth_client.py http://localhost:8080 aauth-test "data.read data.write"

# Request token with resource token
python aauth_client.py http://localhost:8080 aauth-test "eyJhbGciOiJFUzI1NiIsInR5cCI6InJlc291cmNlK2p3dCJ9..."
```

### Using Java (More Accurate)

For production testing, use the actual Keycloak classes. Create a simple Java program:

```java
import org.keycloak.common.util.KeyUtils;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.protocol.aauth.signing.SignatureBaseBuilder;
// ... other imports

public class AAuthClient {
    public static void main(String[] args) throws Exception {
        // Generate key pair
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        
        // Create JWK
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = KeyUtils.createKeyId(keyPair.getPublic());
        String xValue = ((OKPPublicJWK) jwk).getX();
        
        // Build signature headers (similar to integration test)
        // ... (see AAuthDirectGrantTest.createSignedRequestHeaders)
    }
}
```

---

## Validating Responses

### Decode and Validate Auth Token

Use an online JWT decoder or command-line tool:

```bash
# Extract token from response
TOKEN=$(curl ... | jq -r '.auth_token')

# Decode token (using jwt.io or similar)
echo $TOKEN | cut -d. -f2 | base64 -d | jq
```

**Expected Token Structure**:
```json
{
  "typ": "auth+jwt",
  "iss": "http://localhost:8080/realms/aauth-test",
  "aud": "https://agent.example.com",
  "agent": "https://agent.example.com",
  "scope": "data.read data.write",
  "exp": 1234567890,
  "iat": 1234567590,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "..."
    }
  }
}
```

### Verify Token Signature

The token should be signed by Keycloak's realm signing key. Verify using Keycloak's JWKS endpoint:

```bash
curl "http://localhost:8080/realms/aauth-test/protocol/aauth/certs" | jq
```

---

## Troubleshooting

### Keycloak Startup Issues

1. **Build Fails with Protobuf/Protolock Errors**
   - **Error**: `proto-schema-compatibility-check failed` or `An error occurred while running protolock`
   - **Cause**: Network issue fetching proto.lock file or schema compatibility check failing
   - **Fix**: 
     ```bash
     # Skip the proto compatibility check
     ./mvnw clean install -DskipTests -DskipProtoLock=true
     
     # Or build only what you need (avoids the check)
     ./mvnw -pl services,quarkus/server -am clean install -DskipTests
     ```

2. **Build Fails with Dependency Errors**
   - **Cause**: Maven dependencies not resolved
   - **Fix**: 
     ```bash
     # Clean and rebuild with dependency updates
     ./mvnw clean install -DskipTests -U
     # -U forces update of dependencies
     ```

2. **Port 8080 Already in Use**
   - **Cause**: Another service is using port 8080
   - **Fix**: 
     ```bash
     # Option 1: Stop the other service
     # Option 2: Use a different port
     java -jar quarkus/server/target/lib/quarkus-run.jar start-dev --http-port=8081
     # Then update URLs to use port 8081
     ```

3. **"Cannot find quarkus-run.jar" or Build Incomplete**
   - **Cause**: Build didn't complete or wrong path
   - **Fix**: 
     ```bash
     # Rebuild the server (skip test suite)
     ./mvnw -pl core,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true
     # Verify file exists
     ls -la quarkus/server/target/lib/quarkus-run.jar
     ```

4. **Test Suite Compilation Errors (Can Be Ignored)**
   - **Error**: `cannot find symbol: class MediaType` or similar test suite errors
   - **Cause**: Pre-existing compilation issues in Keycloak test suite (not related to AAuth)
   - **Fix**: Skip the test suite entirely - you don't need it for manual testing:
     ```bash
     # Build only server components (excludes test suite)
     ./mvnw -pl core,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true
     ```
   - **Note**: The test suite has known issues. For manual testing, you only need the server to run, not the test suite to compile.

4. **Keycloak Starts but AAuth Endpoints Return 404**
   - **Cause**: AAuth code not compiled or not loaded
   - **Fix**:
     ```bash
     # Rebuild services module
     ./mvnw -pl services clean install -DskipTests
     # Restart Keycloak
     ```

5. **Out of Memory Errors**
   - **Cause**: Insufficient heap space
   - **Fix**:
     ```bash
     # Increase heap size
     export JAVA_OPTS="-Xmx4g"
     java -jar quarkus/server/target/lib/quarkus-run.jar start-dev
     ```

### Common Issues

1. **401 Unauthorized - Invalid Signature**
   - **Cause**: Signature base string doesn't match what Keycloak expects
   - **Fix**: Ensure you're using the exact same components (@method, @authority, @path) and canonical format per RFC 9421

2. **400 Bad Request - Missing Parameters**
   - **Cause**: Both `scope` and `resource_token` are missing
   - **Fix**: Provide exactly one of `scope` or `resource_token`

3. **500 Internal Server Error**
   - **Cause**: Keycloak server error (check logs)
   - **Fix**: Check Keycloak server logs: `tail -f /path/to/keycloak/logs/server.log`

4. **Signature Verification Fails**
   - **Cause**: Public key mismatch or wrong algorithm
   - **Fix**: Verify the `x` parameter in Signature-Key header matches your public key

### Debug Tips

1. **Enable Keycloak Debug Logging**:
   ```bash
   # Add to keycloak.conf or environment
   log-level=DEBUG
   ```

2. **Check Request Headers**:
   ```bash
   curl -v -X POST ...  # Use -v flag to see request/response headers
   ```

3. **Validate Signature Base Locally**:
   - Use Keycloak's `SignatureBaseBuilder` class to build signature base
   - Compare with your implementation

4. **Test with Unit Test Code**:
   - Copy the `createSignedRequestHeaders` method from `AAuthDirectGrantTest.java`
   - Use it to generate correct signatures

---

## Next Steps

After manual testing is successful:

1. **Integration Tests**: Once the test suite build issues are resolved, run `AAuthDirectGrantTest`
2. **External Testing**: Use external AAuth clients (when available)
3. **Performance Testing**: Load test the token endpoint
4. **Security Testing**: Test edge cases and attack scenarios

---

## References

- [AAuth Specification](../SPEC.md)
- [RFC 9421 - HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 8941 - Structured Field Values](https://www.rfc-editor.org/rfc/rfc8941.html)
- [Phase 1 Testing Guide](./AAUTH_PHASE1_TESTING.md)

