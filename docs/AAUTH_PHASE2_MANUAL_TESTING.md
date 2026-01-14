# AAuth Phase 2 Manual Testing Guide

This document provides step-by-step instructions for manually testing the AAuth direct grant flow (`request_type=auth`) once Keycloak is built and running.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Test Scenarios](#test-scenarios)
4. [Troubleshooting](#troubleshooting)

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

**Run**:
```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --scope "data.read data.write"
```

**Expected**: Returns an `auth_token` JWT with the requested scope.

---

### Test 3: Direct Grant with Resource Token

**Purpose**: Request an auth token using a `resource_token` parameter, where a resource authorizes the agent.

**Run**:
```bash
./scripts/test_resource_token_flow.sh
```

This script handles starting the mock resource server, generating tokens, and making the request.

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


---

## References

- [AAuth Specification](../SPEC.md)
- [RFC 9421 - HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 8941 - Structured Field Values](https://www.rfc-editor.org/rfc/rfc8941.html)
- [Phase 1 Testing Guide](./AAUTH_PHASE1_TESTING.md)

