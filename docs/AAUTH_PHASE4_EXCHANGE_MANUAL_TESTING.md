# AAuth Phase 4 Token Exchange Manual Testing Guide

This document provides step-by-step instructions for manually testing the AAuth token exchange flow (`request_type=exchange`) once Keycloak is built and running.

**Focus**: This guide emphasizes **same-server token exchange** (exchanging tokens within the same Keycloak realm), which is the primary use case. Cross-server exchange (federation) is covered as an advanced scenario.

## Table of Contents

1. [Quick Start - Same-Server Exchange](#quick-start---same-server-exchange)
   - [Automated Test Script (Recommended)](#automated-test-script-recommended)
   - [Manual Testing Steps](#manual-testing-steps)
2. [Prerequisites](#prerequisites)
3. [Running Unit Tests](#running-unit-tests)
4. [Same-Server Token Exchange Flow](#same-server-token-exchange-flow)
5. [Test Scenarios](#test-scenarios)
6. [Cross-Server Exchange (Advanced)](#cross-server-exchange-advanced)
7. [Troubleshooting](#troubleshooting)

## Quick Start - Same-Server Exchange

### Automated Test Script (Recommended)

The easiest way to test token exchange is using the automated test script:

```bash
./scripts/test-token-exchange.sh
```

This script automates the **entire token exchange flow**:
1. Starts mock agent server at `http://localhost:9002` (for `scheme=jwks`)
2. Starts mock resource server at `http://localhost:9001`
3. **Phase 1**: Obtains upstream auth token via user consent flow
   - Requests `request_token`
   - Opens browser for authentication (you'll need to login and paste the callback URL)
   - Exchanges authorization code for `auth_token`
4. **Phase 2**: Performs token exchange
   - Creates resource token signed by mock resource server
   - Exchanges upstream token + resource token for new auth token
5. Displays decoded token with `act` claim showing delegation chain
6. Cleans up mock servers on exit

**Prerequisites**:
- Keycloak running at `http://localhost:8080`
- Realm `aauth-test` created with a test user (`test-user` / `password`)
- Python 3 with `cryptography` package installed

**Script Options**:
```bash
# Use different base URL
BASE_URL=http://localhost:9090 ./scripts/test-token-exchange.sh

# Use different realm
REALM=my-realm ./scripts/test-token-exchange.sh

# Skip Phase 1 if you already have an upstream token
./scripts/test-token-exchange.sh --skip-auth --upstream-token <YOUR_TOKEN>

# Use verbose output
./scripts/test-token-exchange.sh --verbose
```

**Sample output**:
```
========================================
  AAuth Token Exchange Test Script
========================================

Base URL:       http://localhost:8080
Realm:          aauth-test
Agent ID:       http://localhost:9002 (identified agent, scheme=jwks)
...

✅ TOKEN EXCHANGE SUCCESSFUL!

New Auth Token (decoded):
{
  "iss": "http://localhost:8080/realms/aauth-test",
  "aud": "http://localhost:9001",
  "agent": "http://localhost:9002",
  "scope": "data.read",
  "act": {
    "sub": "b1a5df63-...",
    "agent": "http://localhost:8080/realms/aauth-test"
  }
}
```

---

### Manual Testing Steps

If you prefer to run each step manually, follow the sections below.

### 1. Build and Start Keycloak

```bash
# Build Keycloak (if not already built)
cd /path/to/keycloak

# Clean build - removes stale class files and rebuilds everything needed
# This includes model/infinispan which is required for Quarkus
rm -rf quarkus/server/target quarkus/deployment/target quarkus/dist/target services/target

./mvnw -pl model/infinispan,services,quarkus/server,quarkus/deployment,quarkus/dist \
  -am clean install -DskipTests -DskipProtoLock=true -q
```

> **Note**: The `-q` flag suppresses most Maven output for cleaner logs. Remove it if you need verbose build output. Including `model/infinispan` prevents `InfinispanUtils cannot be resolved` errors.

```bash
# Start Keycloak with bootstrap admin
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev \
  --bootstrap-admin-username=admin \
  --bootstrap-admin-password=admin
```

**Expected startup output** (clean build):
```
Running the server in development mode. DO NOT use this configuration in production.
2026-01-14 07:36:25,786 INFO  [org.keycloak.quarkus.runtime.storage.infinispan.CacheManagerFactory] Starting Infinispan embedded cache manager
...
2026-01-14 07:36:26,570 INFO  [io.quarkus] Keycloak 26.2.5 on JVM (powered by Quarkus 3.20.1) started in 3.035s. Listening on: http://0.0.0.0:8080
2026-01-14 07:36:26,570 INFO  [io.quarkus] Profile dev activated.
```

**Verify**: Open `http://localhost:8080` - you should see the Keycloak welcome page.

### 2. Create Test Realm and User

**Create Realm:**
```bash
# Create realm via script (if available) or Admin Console
```

**Create Test User (via Admin Console):**
1. Open `http://localhost:8080/admin` (username: `admin`, password: `admin`)
2. Select `aauth-test` realm (or create it)
3. Go to "Users" → "Add user"
4. Username: `test-user`
5. Email: `test@example.com`
6. Toggle "Email Verified" ON
7. Click "Create"
8. Go to "Credentials" tab → Set password: `password` → Toggle "Temporary" OFF → "Set Password"

### 3. Test Same-Server Token Exchange

**Important**: For same-server exchange, **no trust configuration is needed**. The same Keycloak instance automatically trusts its own tokens.

**Step 1: Get Initial Auth Token**

Get an initial `auth_token` from the same Keycloak realm. This requires the user consent flow:

**1a. Request Token (may return request_token if user consent needed):**

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --agent-id "https://agent1.example.com" \
  --scope "profile email data.read data.write" \
  --redirect-uri "http://localhost:9000/callback" \
  --verbose
```

**If the response contains `request_token`** (user consent required):

**1b. Open the authorization URL in your browser:**
```
http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth?request_token=<REQUEST_TOKEN>&redirect_uri=http://localhost:9000/callback
```

**1c. Authenticate and grant consent:**
- Login as `test-user` / `password`
- Grant consent for the requested scopes
- Copy the `code` parameter from the redirect URL

**1d. Exchange code for auth_token:**

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --agent-id "https://agent1.example.com" \
  --code <AUTHORIZATION_CODE> \
  --redirect-uri "http://localhost:9000/callback" \
  --verbose
```

Copy the `auth_token` from the response. This is your `<UPSTREAM_AUTH_TOKEN>`.

**Note**: If the initial request returns `auth_token` directly (no user consent needed), skip steps 1b-1d and use that token.

**Important**: Auth tokens expire after 5 minutes by default. Use the token immediately after obtaining it, or increase the realm's access token lifespan in Realm Settings → Tokens → Access Token Lifespan (e.g., set to 3600 seconds for 1 hour of testing).

**Step 2: Create a Mock Resource Token**

Create a resource token for a different resource (Resource 2) that the agent wants to access:

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --create-mock-resource-token \
  --agent-id "https://agent1.example.com" \
  --aud-agent-id "https://agent1.example.com" \
  --resource-id "https://resource2.example.com" \
  --scope "data.read" \
  --auth-server-id "http://localhost:8080/realms/aauth-test" \
  --verbose
```

Copy the `resource_token` from the response. This is your `<RESOURCE_TOKEN>`.

**Step 3: Exchange Token**

Exchange the upstream token for a new token to access Resource 2. The request will be signed by the same agent (`agent1.example.com`):

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --exchange \
  --upstream-token <UPSTREAM_AUTH_TOKEN> \
  --resource-token <RESOURCE_TOKEN> \
  --scope "data.read" \
  --verbose
```

**Expected Response**:
- `Status: 200`
- A JSON body containing a new `auth_token` and `expires_in`
- The new `auth_token` should have:
  - `iss`: `http://localhost:8080/realms/aauth-test` (same issuer)
  - `aud`: `https://resource2.example.com` (new resource)
  - `agent`: `https://agent1.example.com` (same agent)
  - `sub`: `test-user` (preserved from upstream token)
  - `scope`: `data.read` (narrowed from upstream scope)
  - `act`: An actor claim representing the delegation from the initial token

**Verify Actor Claim**:
```bash
# Decode the new auth_token to see the act claim
python -c "
import sys
import json
import base64

token = sys.argv[1]
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

print('New Auth Token Claims:')
print(json.dumps(payload, indent=2))

if 'act' in payload:
    print('\nActor Claim (shows delegation chain):')
    print(json.dumps(payload['act'], indent=2))
" <NEW_AUTH_TOKEN>
```

The `act` claim should show:
- `agent`: `https://agent1.example.com` (the agent from the upstream token)
- `sub`: `test-user` (the user from the upstream token)

## Prerequisites

### Required Tools

1. **Keycloak Server** - Built and running
2. **Python 3** - For generating signed requests
3. **Browser** (optional) - For user authentication

### Python Dependencies

Install required Python packages:
```bash
pip install cryptography requests python-http-message-signatures
```

## Running Unit Tests

To run the unit tests for token exchange:

```bash
cd services
../mvnw test -Dtest=ExchangeGrantTypeTest,UpstreamAuthTokenValidatorTest,AuthServerTrustManagerTest
```

## Same-Server Token Exchange Flow

### Overview

Same-server token exchange allows a resource acting as an agent to exchange an `auth_token` it received for a new `auth_token` to access a downstream resource, all within the same Keycloak realm.

**Use Case**: Resource 1 receives a request from Agent 1 with an `auth_token` to access Resource 1. Resource 1 needs to call Resource 2 to fulfill the request, so it exchanges the upstream token for a new token to access Resource 2.

### Flow Diagram

```
Agent 1 → Resource 1 (with auth_token for Resource 1)
           ↓
Resource 1 needs to call Resource 2
           ↓
Resource 1 → Keycloak (exchange request)
           - Presents upstream auth_token (scheme=jwt)
           - Presents resource_token from Resource 2
           ↓
Keycloak validates:
           - Upstream token (same issuer, so auto-trusted)
           - Resource token
           - Scope narrowing
           ↓
Keycloak → Resource 1 (new auth_token with act claim)
           ↓
Resource 1 → Resource 2 (with new auth_token)
```

### Request Format

**Endpoint**: `POST /realms/{realm}/protocol/aauth/agent/token`

**Headers:**
```
Content-Type: application/x-www-form-urlencoded
Signature-Key: sig=jwt;jwt=<upstream_auth_token>
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest" "signature-key");created=<timestamp>
Signature: sig1=:<signature>:
```

**Body:**
```
request_type=exchange
resource_token=<resource_token_jwt>
```

### Response Format

**Success Response (200 OK):**
```json
{
  "auth_token": "eyJhbGc...",
  "expires_in": 300,
  "token_type": "AAuth"
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "invalid_grant",
  "error_description": "Token exchange validation failed: <reason>"
}
```

## Test Scenarios

### Scenario 1: Basic Same-Server Exchange

**Goal**: Exchange an auth token for a new token to access a different resource within the same realm.

**Steps:**
1. Get initial `auth_token` for Resource 1
2. Get `resource_token` from Resource 2
3. Exchange tokens (same agent, same Keycloak instance)
4. Verify new token has `act` claim

**Expected Result:**
- New `auth_token` issued
- `act` claim contains upstream agent information
- Token can be used to access Resource 2

### Scenario 2: Scope Narrowing

**Goal**: Verify that exchanged tokens can only have scopes that are subsets of the upstream token's scope.

**Steps:**
1. Get upstream token with scope: `"profile email data.read data.write"`
2. Request exchange with resource token requesting scope: `"data.read"`
3. Verify exchange succeeds
4. Try exchange with resource token requesting scope: `"data.delete"` (not in upstream)
5. Verify exchange fails

**Expected Result:**
- Exchange with subset scope succeeds
- Exchange with expanded scope fails with error

### Scenario 3: User Context Preservation

**Goal**: Verify that user identity (`sub` claim) is preserved through the exchange.

**Steps:**
1. Get upstream token with `sub` claim (user identity)
2. Exchange token
3. Verify new token has same `sub` claim
4. Verify `act.sub` also contains the user identity

**Expected Result:**
- User identity preserved in both new token and `act` claim

### Scenario 4: Multi-Hop Exchange (Nested act Claims)

**Goal**: Test nested delegation chains (token exchange with upstream token that already has an `act` claim).

**Steps:**
1. Get initial upstream token (no `act` claim)
2. Exchange it for intermediate token (has `act` claim)
3. Exchange intermediate token for final token (has nested `act` claim)
4. Verify nested `act` claim structure

**Expected Result:**
- Final token contains nested `act` claim
- Delegation chain is preserved

### Scenario 5: Actor Claim Validation

**Goal**: Verify that the `act` claim correctly represents the upstream agent.

**Steps:**
1. Exchange token with upstream agent: `https://agent1.example.com`
2. Decode the new `auth_token`
3. Verify `act.agent` equals upstream agent
4. Verify `act.sub` equals upstream user (if present)
5. Verify `act.agent_delegate` equals upstream delegate (if present)

**Expected Result:**
- `act` claim correctly represents upstream delegation

## Cross-Server Exchange (Advanced)

**Note**: Cross-server exchange (federation) is supported but not the primary focus. This section covers testing with multiple Keycloak instances.

### Setup for Cross-Server Exchange

**Prerequisites:**
1. Two Keycloak instances running (main server and upstream server)
2. Upstream server configured as trusted in main server

### Configure Trust

**Step 1: Get Upstream Server Issuer**

The upstream server's issuer is typically: `http://localhost:8081/realms/upstream-realm`

**Step 2: Configure Trust in Main Server**

Add the upstream issuer to the main realm's trusted issuers:

**Using Admin Console:**
1. Navigate to Realm Settings → Attributes
2. Add attribute: `aauth.trusted.issuers`
3. Value: `["http://localhost:8081/realms/upstream-realm"]`

**Using Admin REST API:**
```bash
curl -X PUT "http://localhost:8080/admin/realms/aauth-test" \
  -H "Authorization: Bearer $(./scripts/get_admin_token.sh)" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "aauth.trusted.issuers": "[\"http://localhost:8081/realms/upstream-realm\"]"
    }
  }'
```

### Test Cross-Server Exchange

**Step 1: Get Upstream Auth Token**

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8081 \
  --realm upstream-realm \
  --agent-id "https://upstream-agent.example.com" \
  --scope "profile email data.read" \
  --resource-id "https://resource1.example.com" \
  --user-login test-user \
  --user-password password \
  --verbose
```

**Step 2: Create Resource Token**

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --create-mock-resource-token \
  --agent-id "https://current-agent.example.com" \
  --aud-agent-id "https://upstream-agent.example.com" \
  --resource-id "https://resource2.example.com" \
  --scope "data.read" \
  --auth-server-id "http://localhost:8080/realms/aauth-test" \
  --verbose
```

**Step 3: Exchange Token**

```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --exchange \
  --upstream-token <UPSTREAM_AUTH_TOKEN> \
  --resource-token <RESOURCE_TOKEN> \
  --scope "data.read" \
  --verbose
```

**Expected Result:**
- New `auth_token` issued by main server
- `act` claim shows upstream agent from upstream server
- Token can be used to access Resource 2

## Troubleshooting

### Error: "Unresolved compilation problem: Urls cannot be resolved" (or similar)

**Cause**: Stale compiled class files are being loaded by Quarkus. This happens when code changes are made but old `.class` files remain in the target directories.

**Solution**: Perform a clean build that removes target directories:
```bash
rm -rf quarkus/server/target quarkus/deployment/target quarkus/dist/target services/target

./mvnw -pl model/infinispan,services,quarkus/server,quarkus/deployment,quarkus/dist \
  -am clean install -DskipTests -DskipProtoLock=true -q
```

Then restart Keycloak.

### Error: "Missing upstream auth_token"

**Cause**: The request is not signed with `scheme=jwt` containing an `auth+jwt` token.

**Solution**: Ensure the `Signature-Key` header contains `scheme=jwt` with a valid `auth+jwt` token in the `jwt` parameter.

### Error: "Upstream auth server issuer is not trusted"

**Cause**: For cross-server exchange, the upstream auth server's issuer is not in the trusted issuers list.

**Solution**: 
- For **same-server exchange**: This error should not occur. If it does, check that the issuer matches exactly.
- For **cross-server exchange**: Add the upstream issuer to the realm's `aauth.trusted.issuers` attribute.

### Error: "Scope expansion not allowed"

**Cause**: The resource token requests scopes that are not in the upstream token.

**Solution**: Ensure the resource token's scope is a subset of the upstream token's scope.

### Error: "Token exchange validation failed"

**Cause**: Various validation failures (signature, expiration, missing claims, etc.).

**Solution**: 
- Verify upstream token is valid and not expired
- Verify upstream token signature is valid
- Verify upstream token has required claims (`iss`, `exp`, `cnf.jwk`)
- Check Keycloak logs for detailed error messages

### Error: "Delegation chain depth limit exceeded"

**Cause**: The delegation chain is too deep (exceeds maximum depth of 10).

**Solution**: Reduce the number of token exchanges in the chain.

### Error: "Failed to get JWKS from current realm" (Same-Server)

**Cause**: Keycloak cannot retrieve its own realm's JWKS.

**Solution**: 
- Verify Keycloak is running and accessible
- Check realm configuration
- Verify the realm has active signing keys

## Additional Notes

1. **Same-Server Exchange**: No trust configuration needed. The same Keycloak instance automatically trusts its own tokens.

2. **Upstream Token Format**: The upstream `auth_token` must be a valid JWT with `typ="auth+jwt"` header.

3. **Signature Scheme**: Token exchange requires `scheme=jwt` in the `Signature-Key` header, with the upstream token in the `jwt` parameter.

4. **Scope Narrowing**: The exchanged token's scope must be a subset of the upstream token's scope. Scope expansion is not allowed.

5. **Actor Claims**: The `act` claim preserves the delegation chain, allowing resources to verify who originally authorized the request.

6. **Multi-Hop Delegation**: The implementation supports nested `act` claims for multi-hop delegation chains, up to a maximum depth of 10.

7. **User Context**: If the upstream token contains a `sub` claim, it is preserved in the `act` claim and the new token's `sub` claim.

8. **Cross-Server Exchange**: Requires federation trust configuration. See [Cross-Server Exchange](#cross-server-exchange-advanced) section for details.
