# AAuth Phase 3 Manual Testing Guide

This document provides step-by-step instructions for manually testing the AAuth user consent flow (`request_type=code`) once Keycloak is built and running.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Running Unit Tests](#running-unit-tests)
4. [Setup](#setup)
5. [Test Scenarios](#test-scenarios)
6. [User Consent Flow](#user-consent-flow)
7. [Code Exchange Flow](#code-exchange-flow)
8. [Troubleshooting](#troubleshooting)

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

### 3. Test User Consent Flow

**Important**: The Python test client automatically saves and reuses the same key pair across invocations (saved to `.aauth_test_key.pem` by default). This ensures the agent signature matches between the initial request and code exchange. If you want to use a different key file, use `--key-file <path>`.

**Step 1: Request Token (with user scope)**
```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --scope "profile email" \
  --redirect-uri "http://localhost:9000/callback"
```

This should return a `request_token` (not an `auth_token`). The script will automatically generate and save a key pair to `.aauth_test_key.pem` if it doesn't exist.

**Step 2: Open Authorization Endpoint**
Open in browser:
```
http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth?request_token=<request_token>&redirect_uri=http://localhost:9000/callback
```

**Step 3: Authenticate and Grant Consent**
- Login with `test-user` / `password`
- Grant consent (if consent screen is shown)
- You'll be redirected to `http://localhost:9000/callback?code=<authorization_code>`

**Step 4: Exchange Code for Auth Token**
```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --code <authorization_code> \
  --redirect-uri "http://localhost:9000/callback"
```

**Note**: The script will automatically load the same key pair from `.aauth_test_key.pem` that was used in Step 1, ensuring the agent signature matches.

This should return an `auth_token` with user identity (`sub` claim).

## Prerequisites

### Required Tools

1. **Keycloak Server** - Built and running
2. **Python 3** - For generating signed requests
3. **Browser** - For user authentication and consent
4. **curl** (optional) - For manual HTTP requests

### Python Dependencies

```bash
pip install cryptography requests
```

### Key Pair Management

The Python test client (`scripts/aauth_test_client.py`) automatically manages key pairs:

- **First Run**: Generates a new Ed25519 key pair and saves it to `.aauth_test_key.pem` (in the current directory)
- **Subsequent Runs**: Automatically loads the saved key pair from `.aauth_test_key.pem`
- **Custom Key File**: Use `--key-file <path>` to specify a different location

**Important**: The same key pair must be used for both the initial request token and the code exchange. The script handles this automatically, but if you delete `.aauth_test_key.pem` between requests, you'll need to start the flow over from the beginning.

**Security Note**: The `.aauth_test_key.pem` file contains your private key. Keep it secure and don't commit it to version control. Add `.aauth_test_key.pem` to your `.gitignore` if testing in a git repository.

## Running Unit Tests

Before manual testing, you can verify the Phase 3 implementation by running the unit tests.

### Run All Phase 3 Unit Tests

```bash
# From the Keycloak root directory
./mvnw -pl services test -Dtest=AAuthRequestTokenStoreTest,CodeGrantTypeTest -DfailIfNoTests=false
```

This will run:
- **AAuthRequestTokenStoreTest** (5 tests): Tests for request token creation, validation, expiration, and consumption
- **CodeGrantTypeTest** (3 tests): Tests for authorization code creation, storage, and expiration

### Run Individual Test Classes

```bash
# Run only request token store tests
./mvnw -pl services test -Dtest=AAuthRequestTokenStoreTest -DfailIfNoTests=false

# Run only code grant type tests
./mvnw -pl services test -Dtest=CodeGrantTypeTest -DfailIfNoTests=false
```

### Run All AAuth Tests (Phases 1-3)

```bash
# Run all AAuth-related unit tests
./mvnw -pl services test -Dtest="*AAuth*" -DfailIfNoTests=false
```

### Expected Test Results

When tests pass successfully, you should see output like:

```
[INFO] Tests run: 8, Failures: 0, Errors: 0, Skipped: 0
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
```

### Test Coverage

The Phase 3 unit tests cover:

1. **Request Token Management**:
   - Creating request tokens with agent identity, resource, scope, and redirect URI
   - Validating request tokens (including expiration checks)
   - Consuming request tokens (single-use enforcement)
   - Handling invalid or missing tokens

2. **Authorization Code Flow**:
   - Creating authorization codes from request tokens
   - Storing codes in single-use object provider
   - Code expiration handling
   - End-to-end flow from request token to code

### Troubleshooting Test Failures

If tests fail:

1. **Compilation Errors**: Ensure all dependencies are built:
   ```bash
   ./mvnw -pl services clean install -DskipTests
   ```

2. **Missing Classes**: Rebuild the services module:
   ```bash
   ./mvnw -pl services clean test
   ```

3. **Test Timeout**: Some tests may take longer on slower machines. Increase timeout if needed.

## Setup

### Step 1: Build Keycloak

See [Phase 2 Manual Testing Guide](../AAUTH_PHASE2_MANUAL_TESTING.md#step-1-build-keycloak) for detailed build instructions.

### Step 2: Start Keycloak

```bash
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \
  --bootstrap-admin-username=admin \
  --bootstrap-admin-password=admin
```

### Step 3: Create Test Realm

```bash
./scripts/create_realm.sh
```

### Step 4: Create Test User

**Via Admin Console:**
1. Navigate to `http://localhost:8080/admin`
2. Select `aauth-test` realm
3. Go to "Users" → "Add user"
4. Fill in:
   - Username: `test-user`
   - Email: `test@example.com`
   - Email Verified: ON
5. Click "Create"
6. Go to "Credentials" tab
7. Set password: `password`
8. Toggle "Temporary" OFF
9. Click "Set Password"

**Via Admin REST API:**
```bash
# Get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" | jq -r '.access_token')

# Create user
curl -X POST http://localhost:8080/admin/realms/aauth-test/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test-user",
    "email": "test@example.com",
    "enabled": true,
    "emailVerified": true,
    "credentials": [{
      "type": "password",
      "value": "password",
      "temporary": false
    }]
  }'
```

## Test Scenarios

### Scenario 1: User Consent Flow with Profile Scope

**Objective**: Verify that requesting user-specific scopes triggers the consent flow.

**Steps**:

1. **Request Token with User Scope**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --scope "profile email" \
     --redirect-uri "http://localhost:9000/callback"
   ```

   **Note**: On first run, the script will generate a new key pair and save it to `.aauth_test_key.pem`. This key will be automatically reused for the code exchange in step 6.

   **Expected Response**:
   ```json
   {
     "request_token": "abc123.1234567890.hash",
     "expires_in": 600,
     "token_type": "AAuth"
   }
   ```

2. **Open Authorization Endpoint**
   ```
   http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth?request_token=<request_token>&redirect_uri=http://localhost:9000/callback
   ```

3. **Authenticate** (if not already logged in)
   - Username: `test-user`
   - Password: `password`

4. **Grant Consent** (if consent screen is shown)
   - Review requested scopes
   - Click "Allow" or "Grant"

5. **Extract Authorization Code**
   - You'll be redirected to: `http://localhost:9000/callback?code=<code>&state=<state>`
   - Extract the `code` parameter

6. **Exchange Code for Auth Token**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --code <authorization_code> \
     --redirect-uri "http://localhost:9000/callback"
   ```

   **Note**: The script automatically loads the same key pair from `.aauth_test_key.pem` that was used in step 1, ensuring the agent signature matches.

   **Expected Response**:
   ```json
   {
     "auth_token": "eyJ...",
     "expires_in": 300,
     "refresh_token": "refresh_token_...",
     "token_type": "AAuth"
   }
   ```

7. **Validate Auth Token**
   ```bash
   # Decode JWT (using jwt.io or Python)
   python -c "
   import jwt
   import json
   token = '<auth_token>'
   # Remove signature verification for inspection
   decoded = jwt.decode(token, options={'verify_signature': False})
   print(json.dumps(decoded, indent=2))
   "
   ```

   **Expected Claims**:
   - `iss`: `http://localhost:8080/realms/aauth-test`
   - `aud`: Resource identifier
   - `sub`: User ID (e.g., `f:12345678-1234-1234-1234-123456789abc:test-user`)
   - `scope`: `profile email`
   - `cnf.jwk`: Agent's public key

### Scenario 2: Direct Grant Still Works (No Consent)

**Objective**: Verify that non-user scopes still work without consent.

**Steps**:

1. **Request Token with Non-User Scope**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --scope "data.read data.write"
   ```

   **Expected Response**:
   ```json
   {
     "auth_token": "eyJ...",
     "expires_in": 300,
     "token_type": "AAuth"
   }
   ```

   **Note**: No `request_token` should be returned - direct grant should work.

### Scenario 3: Request Token Expiration

**Objective**: Verify that expired request tokens are rejected.

**Steps**:

1. **Get Request Token**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --scope "profile" \
     --redirect-uri "http://localhost:9000/callback" > response.json
   
   REQUEST_TOKEN=$(cat response.json | jq -r '.request_token')
   ```

2. **Wait 11 Minutes** (request tokens expire after 10 minutes)

3. **Try to Use Expired Token**
   ```
   http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth?request_token=$REQUEST_TOKEN
   ```

   **Expected**: Error response indicating token is expired or invalid.

### Scenario 4: Code Exchange with Invalid Code

**Objective**: Verify that invalid authorization codes are rejected.

**Steps**:

1. **Try to Exchange Invalid Code**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --code "invalid-code-123" \
     --redirect-uri "http://localhost:9000/callback"
   ```

   **Expected**: Error response indicating invalid or expired code.

### Scenario 5: Code Exchange with Signature Mismatch

**Objective**: Verify that code exchange fails if agent signature doesn't match.

**Steps**:

1. **Get Request Token with Agent A**
   ```bash
   # Use agent A's key (or let it generate and save to agent_a.key)
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --scope "profile" \
     --redirect-uri "http://localhost:9000/callback" \
     --key-file agent_a.key
   ```

2. **Complete Consent Flow** (get authorization code)

3. **Try to Exchange Code with Agent B's Signature**
   ```bash
   # Use agent B's key (different from agent A)
   # First, generate agent B's key by using a different key file
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --code <code_from_step_2> \
     --redirect-uri "http://localhost:9000/callback" \
     --key-file agent_b.key
   ```

   **Expected**: Error response indicating agent signature mismatch.

**Note**: By default, the script uses `.aauth_test_key.pem` and automatically reuses the same key. To test signature mismatch, you must explicitly use different `--key-file` values for the two requests.

### Scenario 6: Code Exchange with Redirect URI Mismatch

**Objective**: Verify that redirect_uri must match the original request.

**Steps**:

1. **Get Request Token**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --scope "profile" \
     --redirect-uri "http://localhost:9000/callback"
   ```

2. **Complete Consent Flow** (get authorization code)

3. **Try to Exchange Code with Different Redirect URI**
   ```bash
   python scripts/aauth_test_client.py \
     --base-url http://localhost:8080 \
     --realm aauth-test \
     --code <code> \
     --redirect-uri "http://localhost:9001/different-callback"
   ```

   **Expected**: Error response indicating redirect_uri mismatch.

## User Consent Flow

### Flow Diagram

```
Agent                    Auth Server              User Browser
  |                           |                        |
  |-- POST /agent/token ----->|                        |
  |   (scope=profile)         |                        |
  |                           |                        |
  |<-- 200 OK ----------------|                        |
  |   {request_token: "..."}  |                        |
  |                           |                        |
  |-- Redirect User --------->|                        |
  |   /agent/auth?            |                        |
  |   request_token=...       |                        |
  |                           |-- GET /agent/auth ---->|
  |                           |   ?request_token=...  |
  |                           |                        |
  |                           |<-- Redirect to login --|
  |                           |                        |
  |                           |-- POST /login ---------|
  |                           |   (credentials)        |
  |                           |                        |
  |                           |-- Show consent -------|
  |                           |                        |
  |                           |<-- POST /consent ------|
  |                           |   (grant)              |
  |                           |                        |
  |<-- Redirect with code ----|                        |
  |   ?code=...                |                        |
  |                           |                        |
  |-- POST /agent/token ----->|                        |
  |   request_type=code        |                        |
  |   code=...                 |                        |
  |                           |                        |
  |<-- 200 OK ----------------|                        |
  |   {auth_token: "..."}     |                        |
```

### Step-by-Step Flow

1. **Agent Requests Token with User Scope**
   - Agent makes signed POST to `/agent/token`
   - Includes `scope=profile email` (user-specific scopes)
   - Includes `redirect_uri` for callback

2. **Auth Server Evaluates Policy**
   - Determines user consent is required
   - Creates and stores request token
   - Returns `request_token` (not `auth_token`)

3. **Agent Redirects User**
   - Agent redirects user to `/agent/auth?request_token=...&redirect_uri=...`

4. **User Authenticates**
   - If not authenticated, user is redirected to login
   - User enters credentials
   - User is redirected back to authorization endpoint

5. **User Grants Consent**
   - Auth server shows consent screen (or auto-grants in Phase 3)
   - User reviews requested scopes
   - User grants consent

6. **Auth Server Generates Code**
   - Auth server creates authorization code
   - Code is bound to request token and agent signature
   - User is redirected to `redirect_uri?code=...`

7. **Agent Exchanges Code**
   - Agent makes signed POST to `/agent/token`
   - Includes `request_type=code` and `code=...`
   - Auth server validates:
     - Code is valid and not expired
     - Agent signature matches original request
     - Redirect URI matches

8. **Auth Server Issues Tokens**
   - Auth server creates `auth_token` with user identity
   - Includes `refresh_token` for token refresh
   - Returns tokens to agent

## Code Exchange Flow

### Request Format

```http
POST /realms/{realm}/protocol/aauth/agent/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Signature-Input: sig=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=1234567890
Signature: sig=:base64signature:
Signature-Key: sig=(scheme=hwk kty="OKP" crv="Ed25519" x="...")

request_type=code&code=abc123.session456.hash&redirect_uri=http://localhost:9000/callback
```

### Response Format

```json
{
  "auth_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "refresh_token": "refresh_token_...",
  "token_type": "AAuth"
}
```

### Validation Checks

The auth server performs these validations during code exchange:

1. **Code Format**: Code must be in format `{codeId}.{userSessionId}.{hash}`
2. **Code Existence**: Code must exist in store and not be expired
3. **Single-Use**: Code is removed from store after use
4. **Agent Signature**: Current agent signature must match original request
5. **Redirect URI**: Must match the redirect_uri from original request
6. **User Session**: User session must still be valid

## Troubleshooting

### Issue: Request Token Not Returned

**Symptoms**: Direct grant returns `auth_token` instead of `request_token` when user scope is requested.

**Possible Causes**:
- Policy evaluation not working correctly
- Scope not recognized as user scope

**Solution**:
- Check that scope contains user-specific scopes (`profile`, `email`, `openid`)
- Verify `requiresUserConsent()` method in `AuthGrantType`

### Issue: Authorization Endpoint Returns 404

**Symptoms**: `/protocol/aauth/agent/auth` returns 404.

**Possible Causes**:
- Endpoint not registered
- Protocol service not configured

**Solution**:
- Verify `AAuthProtocolService` is registered
- Check that `AAuthAuthorizationEndpoint` is returned from `agentAuth()` method
- Rebuild and restart Keycloak

### Issue: Code Exchange Fails with "Invalid or expired authorization code"

**Symptoms**: Code exchange returns error even with valid code.

**Possible Causes**:
- Code expired (60 second default)
- Code already used (single-use)
- Code format incorrect

**Solution**:
- Ensure code is used within 60 seconds
- Don't reuse codes
- Verify code format: `{codeId}.{userSessionId}.{hash}`

### Issue: Code Exchange Fails with "Agent signature mismatch"

**Symptoms**: Code exchange fails even with valid code.

**Possible Causes**:
- Different agent key used for code exchange
- Agent JKT doesn't match
- Key file was deleted or regenerated between requests

**Solution**:
- **The Python test client automatically handles this**: It saves the key pair to `.aauth_test_key.pem` on first use and reuses it for subsequent requests
- If you manually deleted `.aauth_test_key.pem`, you'll need to start the flow over from Step 1
- To use a specific key file, use `--key-file <path>` consistently across all requests
- Verify agent identity matches between requests by checking the JKT values in the error logs

### Issue: Redirect URI Mismatch

**Symptoms**: Code exchange fails with redirect_uri error.

**Possible Causes**:
- Different redirect_uri used in code exchange
- Redirect URI not stored correctly in request token

**Solution**:
- Use exact same redirect_uri in both requests
- Verify redirect_uri is stored in request token

### Issue: User Not Authenticated

**Symptoms**: Authorization endpoint redirects to login even after authentication.

**Possible Causes**:
- Session expired
- Cookie not set correctly

**Solution**:
- Ensure user is logged in to Keycloak
- Check browser cookies
- Try logging in again

## Manual Testing with curl

### Step 1: Generate Key Pair

```bash
# Generate Ed25519 key pair (requires OpenSSL 1.1.1+)
openssl genpkey -algorithm Ed25519 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem

# Extract public key in JWK format (requires Python)
python3 << EOF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64
import json

with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

public_key = private_key.public_key()
public_bytes = public_key.public_bytes_raw()
x = base64.urlsafe_b64encode(public_bytes).decode().rstrip('=')

jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": x
}
print(json.dumps(jwk, indent=2))
EOF
```

### Step 2: Create Signed Request

For manual testing with curl, you'll need to:
1. Generate HTTP Message Signature (complex - use Python script instead)
2. Include Signature-Key, Signature-Input, and Signature headers
3. **Manage key pairs manually** - ensure the same key is used for both request token and code exchange

**Recommendation**: Use the Python test client script (`scripts/aauth_test_client.py`) instead of curl for signed requests. The Python script:
- Automatically generates and saves key pairs (`.aauth_test_key.pem`)
- Handles HTTP Message Signing correctly
- Reuses the same key pair across requests automatically
- Provides verbose output for debugging

## Next Steps

After completing Phase 3 testing:

1. **Phase 4**: Token exchange and refresh flows
2. **Phase 5**: Advanced features (token encryption, auth request documents, etc.)

## References

- [AAuth Specification](../../SPEC.md)
- [Phase 2 Manual Testing Guide](../AAUTH_PHASE2_MANUAL_TESTING.md)
- [RFC 9421 - HTTP Message Signing](https://www.rfc-editor.org/rfc/rfc9421.html)

