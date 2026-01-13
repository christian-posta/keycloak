# AAuth Phase 4 Manual Testing Guide

This document provides step-by-step instructions for manually testing the AAuth refresh token flow (`request_type=refresh`) once Keycloak is built and running.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Running Unit Tests](#running-unit-tests)
4. [Setup](#setup)
5. [Test Scenarios](#test-scenarios)
6. [Refresh Token Flow](#refresh-token-flow)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Build and Start Keycloak

```bash
# Build Keycloak (if not already built)
cd /path/to/keycloak

# Build services + server
./mvnw -pl core,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true

# Start Keycloak with bootstrap admin
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \
  --bootstrap-admin-username=admin \
  --bootstrap-admin-password=admin
```

**Verify**: Open `http://localhost:8080` - you should see the Keycloak welcome page.

### 2. Create Test Realm and User

**Create Realm:**
```bash
./scripts/create_realm.sh
```

**Create Test User (via Admin Console):**
1. Open `http://localhost:8080/admin` (username: `admin`, password: `admin`)
2. Select `aauth-test` realm
3. Go to "Users" → "Add user"
4. Username: `test-user`
5. Email: `test@example.com`
6. Toggle "Email Verified" ON
7. Click "Create"
8. Go to "Credentials" tab → Set password: `password` → Toggle "Temporary" OFF → "Set Password"

### 3. Test Refresh Token Flow

**Important**: The Python test client automatically saves and reuses the same key pair across invocations (saved to `.aauth_test_key.pem` by default). This ensures the agent signature matches between token issuance and refresh.

**Step 1: Get Initial Tokens (via Code Exchange)**
```bash
# First, get a request token
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --scope "profile email" \
  --redirect-uri "http://localhost:9000/callback"

# This returns a request_token. Open the authorization URL in browser:
# http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth?request_token=<request_token>&redirect_uri=http://localhost:9000/callback
# Login and get the authorization code from the redirect URL

# Exchange code for tokens (includes refresh_token)
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --code <authorization_code> \
  --redirect-uri "http://localhost:9000/callback"
```

This should return both `auth_token` and `refresh_token`.

**Step 2: Refresh Auth Token**
```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --refresh-token <refresh_token>
```

This should return a new `auth_token` (refresh token remains valid).

## Prerequisites

### Required Tools

1. **Keycloak Server** - Built and running
2. **Python 3** - For generating signed requests
3. **Browser** - For user authentication (for code exchange flow)
4. **curl** (optional) - For manual HTTP requests

### Python Dependencies

Install required Python packages:
```bash
pip install cryptography requests
```

## Running Unit Tests

Before manual testing, verify that unit tests pass:

```bash
# Run all AAuth unit tests
./mvnw -pl services test -Dtest="*AAuth*Test,*RefreshGrantTypeTest"

# Or run specific refresh token tests
./mvnw -pl services test -Dtest="RefreshGrantTypeTest"
```

**Expected Output**: All tests should pass.

## Setup

### Keycloak Build

If you haven't built Keycloak yet:

```bash
# Clean and build services + server
./mvnw -pl core,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true
```

### Keycloak Startup

Start Keycloak in development mode:

```bash
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \
  --bootstrap-admin-username=admin \
  --bootstrap-admin-password=admin
```

**Note**: The `--bootstrap-admin-username` and `--bootstrap-admin-password` flags create an admin user automatically. Without these flags, you'll need to create the admin user via the web UI.

### Realm Creation

Create the test realm:

```bash
./scripts/create_realm.sh
```

Or manually via Admin Console:
1. Open `http://localhost:8080/admin`
2. Click "Create realm"
3. Realm name: `aauth-test`
4. Click "Create"

### User Creation

Create a test user (required for code exchange flow):

1. Open `http://localhost:8080/admin`
2. Select `aauth-test` realm
3. Go to "Users" → "Add user"
4. Username: `test-user`
5. Email: `test@example.com`
6. Toggle "Email Verified" ON
7. Click "Create"
8. Go to "Credentials" tab
9. Set password: `password`
10. Toggle "Temporary" OFF
11. Click "Set Password"

## Test Scenarios

### Scenario 1: Basic Refresh Flow

**Objective**: Verify that an agent can refresh an expired auth token using a refresh token.

**Steps**:
1. Get initial tokens (auth_token + refresh_token) via code exchange
2. Wait for auth_token to expire (or use a short-lived token)
3. Use refresh_token to get a new auth_token
4. Verify new auth_token is valid and contains correct claims

**Expected Result**: New auth_token is issued with same agent/resource binding.

### Scenario 2: Agent Binding Validation

**Objective**: Verify that refresh tokens are bound to agent identity.

**Steps**:
1. Get tokens with agent key A
2. Try to refresh with agent key B (different key, same or different agent ID)
3. Verify refresh fails with agent signature mismatch

**Expected Result**: Refresh fails with error indicating agent binding mismatch.

### Scenario 3: Refresh Token Expiration

**Objective**: Verify that expired refresh tokens cannot be used.

**Steps**:
1. Get tokens
2. Parse refresh_token to check expiration
3. Wait for refresh_token to expire (or use a short-lived refresh token)
4. Try to refresh with expired refresh_token
5. Verify refresh fails

**Expected Result**: Refresh fails with error indicating expired token.

### Scenario 4: Scope Narrowing

**Objective**: Verify that refresh can request a subset of original scopes.

**Steps**:
1. Get tokens with scope "profile email"
2. Refresh with scope "profile" (narrower scope)
3. Verify new auth_token has only "profile" scope

**Expected Result**: New auth_token has narrowed scope.

**Note**: Scope narrowing is supported but not yet implemented in the Python client. This can be tested manually with curl.

### Scenario 5: Multiple Refreshes

**Objective**: Verify that refresh tokens can be used multiple times (no rotation).

**Steps**:
1. Get tokens
2. Refresh auth_token multiple times using the same refresh_token
3. Verify all refreshes succeed

**Expected Result**: All refreshes succeed (refresh token remains valid).

## Refresh Token Flow

### Overview

The refresh token flow allows agents to obtain new auth tokens without requiring user re-authentication. Refresh tokens are bound to agent identity and must be validated against the agent's HTTP signature.

### Flow Diagram

```
Agent                    Auth Server
  |                          |
  |-- POST /agent/token ---->|
  |   (request_type=refresh) |
  |   Signed with HTTPSig    |
  |                          |
  |<-- {auth_token} ---------|
  |                          |
```

### Step-by-Step Process

1. **Agent Requests Refresh**
   - Agent sends POST to `/realms/{realm}/protocol/aauth/agent/token`
   - `request_type=refresh`
   - `refresh_token=<refresh_token>`
   - Request is signed with HTTPSig

2. **Auth Server Validates**
   - Verifies HTTP signature
   - Extracts agent identity from signature
   - Validates refresh token (signature, expiration, type)
   - Verifies agent binding (agent ID/JKT matches)

3. **Auth Server Issues New Token**
   - Generates new auth_token
   - Returns `{auth_token, expires_in, token_type}`

### Using Python Test Client

The Python test client supports refresh token flow:

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --refresh-token <refresh_token>
```

**Key Features**:
- Automatically loads agent key from `.aauth_test_key.pem`
- Signs request with HTTPSig
- Parses and displays response

### Manual Testing with curl

You can also test manually with curl (requires generating signed headers):

```bash
# Note: This is simplified - actual implementation requires HTTPSig signing
curl -X POST http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Signature: <signature>" \
  -H "Signature-Input: <signature-input>" \
  -H "Signature-Key: <signature-key>" \
  -d "request_type=refresh&refresh_token=<refresh_token>"
```

**Note**: Generating proper HTTPSig headers manually is complex. Use the Python script for easier testing.

## Troubleshooting

### Error: "Agent identity not found"

**Cause**: Request is not signed with HTTPSig, or signature verification failed.

**Solution**:
- Ensure request includes `Signature`, `Signature-Input`, and `Signature-Key` headers
- Verify agent key pair matches the one used to create the refresh token
- Check that Python script is using the correct key file

### Error: "Invalid refresh_token"

**Cause**: Refresh token is malformed, expired, or has invalid signature.

**Solution**:
- Verify refresh token is a valid JWT
- Check refresh token expiration
- Ensure refresh token was issued by the same Keycloak instance

### Error: "Agent signature mismatch"

**Cause**: Agent key used for refresh doesn't match the key bound to the refresh token.

**Solution**:
- Ensure same key pair is used for refresh as was used for token issuance
- Verify Python script is loading the correct key file (`.aauth_test_key.pem`)
- Check that agent ID/JKT matches between refresh token and current signature

### Error: "Refresh token expired"

**Cause**: Refresh token has passed its expiration time.

**Solution**:
- Get a new refresh token via code exchange
- Check realm's `ssoSessionMaxLifespan` setting (default: 30 days)

### Refresh Token Not Returned

**Cause**: Code exchange didn't return a refresh token.

**Solution**:
- Verify code exchange was successful
- Check that user session is valid
- Ensure realm allows refresh tokens

### Key Pair Mismatch

**Cause**: Different key pair used between token issuance and refresh.

**Solution**:
- Python script automatically manages key persistence (saves to `.aauth_test_key.pem`)
- If using multiple agents, use `--key-file <path>` to specify different key files
- Ensure same key file is used for both issuance and refresh

## Response Format

### Success Response

```json
{
  "auth_token": "eyJ0eXAiOiJhdXRoK2p3dCIsImFsZyI6IkVkRFNBIiwi...",
  "expires_in": 300,
  "token_type": "AAuth"
}
```

### Error Response

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid refresh_token: Agent signature mismatch"
}
```

## Validation

### Verify Auth Token

Parse the auth token to verify claims:

```python
import base64
import json

# Decode JWT (simplified - use proper JWT library)
token = "<auth_token>"
parts = token.split(".")
payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

print("Agent:", payload.get("agent"))
print("Resource:", payload.get("aud"))
print("Scope:", payload.get("scope"))
print("Expiration:", payload.get("exp"))
```

### Verify Refresh Token

Parse the refresh token to verify agent binding:

```python
# Decode refresh token
refresh_token = "<refresh_token>"
parts = refresh_token.split(".")
payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

print("Agent:", payload.get("agent"))
print("Agent JKT:", payload.get("agent_jkt"))
print("Resource:", payload.get("resource_id"))
print("Expiration:", payload.get("exp"))
```

## Next Steps

After Phase 4 is complete, you can:

1. Test token exchange flow (Phase 5)
2. Test refresh token rotation (if implemented)
3. Test refresh token revocation
4. Test refresh with different scopes (scope narrowing)

## References

- [AAuth Specification](https://datatracker.ietf.org/doc/draft-parecki-aauth/)
- [Phase 3 Testing Guide](AAUTH_PHASE3_MANUAL_TESTING.md)
- [Python Test Client](../scripts/aauth_test_client.py)

