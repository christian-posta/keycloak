# AAuth Spec Update Implementation Plan

This document describes the changes needed to bring the Keycloak AAuth implementation
into alignment with the updated AAuth specification (SPEC_UPDATED.md, dated March 2026).

The current implementation was built against an earlier draft. The updated spec introduces
significant changes to the transport layer (202+Location polling replaces auth code exchange),
eliminates refresh tokens, restructures the token endpoint, and adds new concepts like
interaction codes, approval states, and clarification chat.

---

## Table of Contents

1. [Phase 1: Pending Request Store & Pending URL Endpoint](#phase-1)
2. [Phase 2: Token Endpoint Restructuring (202 Deferred Responses)](#phase-2)
3. [Phase 3: Interaction Endpoint (Replaces Authorization Endpoint)](#phase-3)
4. [Phase 4: Eliminate Authorization Code Flow](#phase-4)
5. [Phase 5: Eliminate Refresh Tokens (Expired Auth Token Refresh)](#phase-5)
6. [Phase 6: AAuth Response Header](#phase-6)
7. [Phase 7: Metadata Endpoint Updates](#phase-7)
8. [Phase 8: Token Response & Representation Cleanup](#phase-8)
9. [Phase 9: Approval Flow (Out-of-Band)](#phase-9)
10. [Phase 10: Clarification Chat (Optional)](#phase-10)
11. [Phase 11: Token Endpoint Call Chaining (upstream_token)](#phase-11)
12. [Phase 12: Test Updates](#phase-12)
13. [File-by-File Change Summary](#file-summary)

---

<a id="phase-1"></a>
## Phase 1: Pending Request Store & Pending URL Endpoint

The most fundamental new concept: a polling endpoint where agents retrieve results.

### 1.1 New: `AAuthPendingRequest` (replaces conceptual role of `AAuthRequestToken`)

**File:** `services/src/main/java/org/keycloak/protocol/aauth/storage/AAuthPendingRequest.java`

Create a new data class representing a pending authorization request. This replaces the
combined role of `AAuthRequestToken` + `AAuthAuthorizationCode`. A single pending request
lives from the initial 202 response through polling until terminal resolution.

```
Fields:
  - id: String                    // UUID, used in pending URL path
  - status: String                // "pending", "completed", "denied", "abandoned", "expired"
  - agentId: String               // Agent identifier
  - agentJkt: String              // Agent JWK thumbprint
  - signatureScheme: String       // Signature scheme used
  - resourceId: String            // Resource identifier (null for self-access)
  - scope: String                 // Requested scopes
  - purpose: String               // Human-readable purpose (new in spec)
  - requireType: String           // "interaction" or "approval"
  - interactionCode: String       // Short alphanumeric code (e.g., "ABCD1234")
  - callbackUrl: String           // Agent's callback URL (optional, UX only)
  - authToken: String             // The auth_token JWT, set when completed
  - expiresIn: int                // Auth token expiration (set when completed)
  - userSessionId: String         // Set after user authenticates
  - resourceToken: String         // Original resource_token (for validation context)
  - error: String                 // Error code if terminal error
  - errorDescription: String      // Error description
  - createdAt: int                // Timestamp
  - expiresAt: int                // Pending request expiration
  - clarificationQuestion: String // Current clarification question (optional)
  - loginHint: String             // login_hint from agent (optional)
  - tenant: String                // tenant from agent (optional)

Methods:
  - serialize() → Map<String, String>
  - static deserialize(Map<String, String>) → AAuthPendingRequest
  - isPending() → boolean
  - isTerminal() → boolean
  - Getters/setters
```

### 1.2 New: `AAuthPendingRequestStore`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/storage/AAuthPendingRequestStore.java`

Manages lifecycle of pending requests using `SingleUseObjectProvider`.

```
Methods:
  - createPendingRequest(...) → AAuthPendingRequest
      Generates UUID id, generates interaction code, stores with TTL (600s)
  - getPendingRequest(id) → AAuthPendingRequest
      Retrieves by ID (non-consuming — polling must be repeatable)
  - updatePendingRequest(id, AAuthPendingRequest) → void
      Updates stored data (e.g., set authToken when consent completes)
  - completePendingRequest(id, authToken, expiresIn) → void
      Sets status=completed, stores auth token
  - failPendingRequest(id, error, errorDescription) → void
      Sets terminal error status
  - consumePendingRequest(id) → AAuthPendingRequest
      Retrieves and removes (called after terminal response delivered)
  - generateInteractionCode() → String
      Generates short alphanumeric code: 8 chars, A-Z 0-9 (per spec: unreserved URI chars)
```

**Key difference from current `AAuthRequestTokenStore`:** The pending request is NOT
consumed on first read. It persists across multiple GET polls until a terminal response
is delivered, at which point it is consumed. The store must support updates (status
changes, auth token insertion).

**Implementation note:** `SingleUseObjectProvider` supports `put`, `get`, and `remove`
but not `replace`. To update, we'll need to `remove` then `put` with remaining TTL, or
use a different store (e.g., `ActionTokenStoreProvider` or a simple `InfinispanCache`).
Evaluate which Keycloak store supports update semantics. If `SingleUseObjectProvider`
is insufficient, consider using the `ActionTokenStoreProvider` or storing pending requests
as session notes on a lightweight session.

**Alternative approach:** Use `SingleUseObjectProvider` with a pattern where the pending
request ID maps to data, and we remove+re-put on every update. Calculate remaining TTL
from `expiresAt - Time.currentTime()`. This is simple and works within existing infra.

### 1.3 New: `AAuthPendingEndpoint`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/endpoints/AAuthPendingEndpoint.java`

New JAX-RS resource handling `GET /protocol/aauth/pending/{id}` and
`POST /protocol/aauth/pending/{id}` (for clarification chat only).

```java
@Path("pending/{id}")
public class AAuthPendingEndpoint {

    @GET
    public Response poll(@PathParam("id") String pendingId) {
        // 1. Verify agent HTTP signature (filter already does this)
        // 2. Load pending request by ID
        // 3. Verify agent identity matches (agentJkt must match signer)
        // 4. Read Prefer: wait=N header
        // 5. If status == completed:
        //      Return 200 { "auth_token": "...", "expires_in": ... }
        //      Consume (delete) the pending request
        // 6. If status == denied:
        //      Return 403 { "error": "denied", "error_description": "..." }
        //      Consume
        // 7. If status == abandoned:
        //      Return 403 { "error": "abandoned" }
        //      Consume
        // 8. If status == expired:
        //      Return 408 { "error": "expired" }
        //      Consume
        // 9. If status == pending:
        //      If clarificationQuestion is set:
        //          Return 202 { "status": "pending", "location": "...", "clarification": "..." }
        //      Else:
        //          Return 202 { "status": "pending", "location": "...",
        //                       "require": "<interaction|approval>",
        //                       "code": "<if interaction>" }
        //      Set headers: Location, Retry-After: 0, Cache-Control: no-store
        //      Set AAuth header
        // 10. If not found: Return 404
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response clarify(@PathParam("id") String pendingId, Map<String, String> body) {
        // Clarification chat (Phase 10)
        // Only valid when pending request has a clarification question
    }
}
```

**Long-polling (Prefer: wait=N):** The spec says agents send `Prefer: wait=45`.
For initial implementation, we can ignore the wait preference and return immediately
(the agent will poll). Long-polling optimization can be added later using Keycloak's
async/reactive infrastructure or a simple Thread.sleep with interrupt on status change.

**Important:** After delivering a terminal response (200, 403, 408, 410), the pending
URL must return 404 on subsequent requests. This means we must delete the pending request
from the store after the first terminal response.

### 1.4 Register Pending Endpoint in `AAuthProtocolService`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/AAuthProtocolService.java`

Add new path:
```java
@Path("pending/{id}")
public Object pending(@PathParam("id") String pendingId) {
    return new AAuthPendingEndpoint(session, event, pendingId);
}
```

### 1.5 Update `AAuthSignatureFilter` for Pending Endpoint

**File:** `services/src/main/java/org/keycloak/protocol/aauth/filters/AAuthSignatureFilter.java`

The filter currently intercepts all `/protocol/aauth/` paths except `/.well-known/`.
The pending endpoint MUST be signature-verified (spec says "Servers MUST verify the
agent's identity on every GET poll"). The filter should already handle this since it
matches `/protocol/aauth/pending/*`, but verify that GET requests are also covered
(currently the filter may only cover POST).

---

<a id="phase-2"></a>
## Phase 2: Token Endpoint Restructuring (202 Deferred Responses)

### 2.1 Restructure `AAuthTokenEndpoint` — Remove `request_type` Routing

**File:** `services/src/main/java/org/keycloak/protocol/aauth/endpoints/AAuthTokenEndpoint.java`

The current endpoint reads `request_type` from form params and dispatches to different
`OAuth2GrantType` providers. The updated spec has a single token endpoint that auto-detects
the mode from which parameters are present.

**Change the endpoint to accept JSON (not form-encoded):**

The updated spec (section 19.8) explicitly uses JSON for request bodies:
```
POST /token HTTP/1.1
Content-Type: application/json
{ "resource_token": "eyJ...", "purpose": "Find available meeting times" }
```

Current implementation uses `@Consumes(MediaType.APPLICATION_FORM_URLENCODED)`. Change to:
```java
@Consumes(MediaType.APPLICATION_JSON)
@POST
public Response processTokenRequest(Map<String, Object> body) {
    // Auto-detect mode from parameters present:
    // 1. body.containsKey("resource_token") && body.containsKey("upstream_token")
    //      → Call chaining mode
    // 2. body.containsKey("resource_token")
    //      → Resource access mode
    // 3. body.containsKey("scope") && !body.containsKey("resource_token")
    //      → Self-access (SSO/1P) mode
    // 4. body.containsKey("auth_token")
    //      → Token refresh mode
    // Route to appropriate handler method
}
```

**Keep form-encoded as a fallback** if backward compatibility is needed during migration,
but prefer JSON as the primary format per spec.

### 2.2 Rewrite `AuthGrantType` → New Authorization Handler

**File:** `services/src/main/java/org/keycloak/protocol/aauth/grants/AuthGrantType.java`

This is the core change. When consent is required, the response changes from:
```
Current:  200 OK { "request_token": "...", "expires_in": 600, "token_type": "AAuth" }
```
to:
```
Updated:  202 Accepted
          Location: /pending/abc123
          Retry-After: 0
          Cache-Control: no-store
          AAuth: require=interaction; code="ABCD1234"
          Content-Type: application/json

          { "status": "pending",
            "location": "/pending/abc123",
            "require": "interaction",
            "code": "ABCD1234" }
```

**Changes to `processGrant()` method:**

```java
if (requiresConsent) {
    // OLD: Issue request_token, return 200
    // NEW: Create pending request, return 202

    AAuthPendingRequestStore pendingStore = new AAuthPendingRequestStore(session);
    AAuthPendingRequest pending = pendingStore.createPendingRequest(
        agentId, agentJkt, signatureScheme, resourceId, grantedScope,
        purpose, "interaction" /* requireType */);

    String pendingPath = "/realms/" + realm.getName() + "/protocol/aauth/pending/" + pending.getId();

    // Build 202 response
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("status", "pending");
    body.put("location", pendingPath);
    body.put("require", "interaction");
    body.put("code", pending.getInteractionCode());

    return cors.add(Response.status(202)
        .header("Location", pendingPath)
        .header("Retry-After", "0")
        .header("Cache-Control", "no-store")
        .header("AAuth", "require=interaction; code=\"" + pending.getInteractionCode() + "\"")
        .entity(body)
        .type(MediaType.APPLICATION_JSON_TYPE));
}
```

**Read `Prefer: wait=N` header:** Parse the `Prefer` request header. For now, ignore
the wait value (return 202 immediately). Future enhancement: hold connection open.

**Read `purpose` parameter:** Extract from request body and store in pending request.

### 2.3 Direct Grant Response (No Change in Shape)

When consent is NOT required, the response remains:
```json
{ "auth_token": "eyJ...", "expires_in": 3600 }
```
But remove `"token_type": "AAuth"` — the updated spec does not include this field.

---

<a id="phase-3"></a>
## Phase 3: Interaction Endpoint (Replaces Authorization Endpoint)

### 3.1 Rewrite `AAuthAuthorizationEndpoint` → `AAuthInteractionEndpoint`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/endpoints/AAuthAuthorizationEndpoint.java`
→ Rename to `AAuthInteractionEndpoint.java`

The interaction endpoint is where users go (via browser) to authenticate and consent.

**Key changes:**

| Aspect | Current | Updated |
|--------|---------|---------|
| URL path | `/agent/auth` | `/interact` (or keep `/agent/auth`, just change behavior) |
| Input param | `request_token=<opaque>` | `code=ABCD1234` |
| Callback param | `redirect_uri` | `callback` (optional, UX only) |
| After consent | Redirect with auth code | Redirect to callback (no code/token), OR show completion page |
| Auth token delivery | Via code exchange at token endpoint | Via polling GET on pending URL |

**Updated flow:**

```
GET /interact?code=ABCD1234&callback=https://agent.example/callback?state=xyz
```

1. Look up pending request by interaction code (not by opaque token)
2. If no match → error page "Invalid or expired interaction code"
3. Check if user authenticated (SSO cookie)
4. If not → redirect to login (store interaction code in auth session)
5. If authenticated, check session consent
6. If already consented → complete the pending request (set auth token), redirect to callback
7. If not consented → show consent screen

**After consent is granted:**

```java
// OLD: Generate authorization code, redirect with code
// NEW: Complete the pending request, redirect to callback (no code)

// 1. Generate auth token
String authToken = tokenManager.createAuthToken(realm, agentId, agentDelegate,
    agentPublicKey, resourceId, grantedScope, userSubject);

// 2. Complete the pending request (agent's next poll will get the auth token)
pendingStore.completePendingRequest(pendingRequest.getId(), authToken, expiresIn);

// 3. Redirect to callback (if provided) or show completion page
if (callbackUrl != null) {
    return Response.seeOther(URI.create(callbackUrl)).build();
} else {
    return showCompletionPage(); // "You may close this window"
}
```

**The callback URL has no security role** — it carries no code, no token. It just
signals the agent to poll. An attacker intercepting the callback can only cause the
agent to poll sooner; no secrets are exposed.

### 3.2 Update `AAuthLoginProtocol.authenticated()`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/AAuthLoginProtocol.java`

After user authenticates via Keycloak login, this method is called. Currently it
redirects to `/agent/auth?request_token=...`. Update to redirect to the interaction
endpoint with the interaction code instead:

```java
// OLD: redirect to /agent/auth?request_token=...
// NEW: redirect to /interact?code=...&callback=...
```

Store interaction code (not request_token) in the auth session's client notes.

### 3.3 Update Consent Screen

**File:** `services/src/main/resources/theme-resources/templates/login-aauth-grant.ftl`

Minor changes:
- The consent form POST should now signal completion of the pending request
  (not generate an auth code)
- The consent action URL changes to match the new endpoint path
- Add display of `purpose` field from the agent's request

**File:** `services/src/main/java/org/keycloak/protocol/aauth/forms/AAuthConsentBean.java`

Add `purpose` field to the consent bean so the template can display it.

### 3.4 Interaction Code Lookup

Need an index from interaction code → pending request ID. Options:

**Option A (simple):** Store a separate mapping `interactionCode → pendingRequestId` in
`SingleUseObjectProvider`. When the user hits `/interact?code=ABCD1234`, look up the
pending request ID, then load the full pending request.

**Option B (scan):** Store the interaction code as a field in the pending request and
scan. Not efficient — avoid.

**Recommended: Option A.** In `AAuthPendingRequestStore.createPendingRequest()`:
```java
// Store code→id mapping
Map<String, String> codeMapping = Map.of("pending_request_id", pendingRequest.getId());
session.singleUseObjects().put("aauth.code." + interactionCode, 600, codeMapping);
```

Lookup:
```java
public AAuthPendingRequest getByInteractionCode(String code) {
    Map<String, String> mapping = session.singleUseObjects().get("aauth.code." + code);
    if (mapping == null) return null;
    return getPendingRequest(mapping.get("pending_request_id"));
}
```

---

<a id="phase-4"></a>
## Phase 4: Eliminate Authorization Code Flow

### 4.1 Delete `CodeGrantType.java` and `CodeGrantTypeFactory.java`

**Files to delete:**
- `services/src/main/java/org/keycloak/protocol/aauth/grants/CodeGrantType.java`
- `services/src/main/java/org/keycloak/protocol/aauth/grants/CodeGrantTypeFactory.java`

### 4.2 Delete `AAuthAuthorizationCode.java`

**File to delete:**
- `services/src/main/java/org/keycloak/protocol/aauth/storage/AAuthAuthorizationCode.java`

### 4.3 Remove Code-Related SPI Registration

**File:** Check `META-INF/services/org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory`
(or similar) for the CodeGrantType registration and remove it.

### 4.4 Deprecate `AAuthRequestToken` and `AAuthRequestTokenStore`

These are replaced by `AAuthPendingRequest` and `AAuthPendingRequestStore`. Once all
references are migrated, delete:
- `services/src/main/java/org/keycloak/protocol/aauth/storage/AAuthRequestToken.java`
- `services/src/main/java/org/keycloak/protocol/aauth/storage/AAuthRequestTokenStore.java`

---

<a id="phase-5"></a>
## Phase 5: Eliminate Refresh Tokens (Expired Auth Token Refresh)

### 5.1 Delete `RefreshGrantType.java` and `RefreshGrantTypeFactory.java`

**Files to delete:**
- `services/src/main/java/org/keycloak/protocol/aauth/grants/RefreshGrantType.java`
- `services/src/main/java/org/keycloak/protocol/aauth/grants/RefreshGrantTypeFactory.java`

### 5.2 Delete `AAuthRefreshToken.java`

**File to delete:**
- `core/src/main/java/org/keycloak/representations/AAuthRefreshToken.java`

### 5.3 Remove Refresh Token Creation from `AAuthTokenManager`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/AAuthTokenManager.java`

- Delete `createRefreshToken()` method
- Delete `validateRefreshToken()` method
- Keep `refreshAuthToken()` but rewrite it to accept an expired auth token:

```java
/**
 * Refresh by re-presenting an expired auth token.
 * Verify the JWT signature (even though it's expired), verify agent binding,
 * then issue a new auth token with the same claims.
 */
public String refreshFromExpiredAuthToken(RealmModel realm, String expiredAuthTokenJwt,
        PublicKey agentPublicKey) {
    // 1. Parse the expired JWT (skip exp validation)
    // 2. Verify JWT signature using auth server's own JWKS
    // 3. Verify cnf.jwk matches agentPublicKey
    // 4. Extract claims: aud, agent, scope, sub
    // 5. Check refresh window (auth server MAY reject if too old)
    // 6. Issue new auth token with same claims
    return createAuthToken(realm, agent, agentDelegate, agentPublicKey,
            audience, scope, subject);
}
```

### 5.4 Add Refresh Mode to Token Endpoint

**File:** `services/src/main/java/org/keycloak/protocol/aauth/endpoints/AAuthTokenEndpoint.java`

In the restructured token endpoint (Phase 2), add handling for the refresh mode:

```java
if (body.containsKey("auth_token") && !body.containsKey("resource_token")) {
    // Token refresh mode
    String expiredToken = (String) body.get("auth_token");
    String newAuthToken = tokenManager.refreshFromExpiredAuthToken(realm, expiredToken, agentPublicKey);
    return Response.ok(Map.of("auth_token", newAuthToken, "expires_in", expiresIn)).build();
}
```

### 5.5 Remove `refresh_token` from Token Responses

**File:** `services/src/main/java/org/keycloak/protocol/aauth/grants/CodeGrantType.java`
(already deleted in Phase 4, but mentioned for completeness)

All token responses must stop including `refresh_token`. The response is simply:
```json
{ "auth_token": "eyJ...", "expires_in": 3600 }
```

---

<a id="phase-6"></a>
## Phase 6: AAuth Response Header

The updated spec defines a structured HTTP response header `AAuth` used on both 401
and 202 responses. This is a new concept not present in the current implementation.

### 6.1 New: `AAuthResponseHeader` Utility

**File:** `services/src/main/java/org/keycloak/protocol/aauth/AAuthResponseHeader.java`

Utility class to build the AAuth structured header per RFC 8941:

```java
public class AAuthResponseHeader {

    public static String pseudonymRequired() {
        return "require=pseudonym";
    }

    public static String identityRequired() {
        return "require=identity";
    }

    public static String authTokenRequired(String resourceToken, String authServer) {
        return "require=auth-token; resource-token=\"" + resourceToken
            + "\"; auth-server=\"" + authServer + "\"";
    }

    public static String interactionRequired(String code) {
        return "require=interaction; code=\"" + code + "\"";
    }

    public static String approvalPending() {
        return "require=approval";
    }
}
```

### 6.2 Add AAuth Header to 202 Responses

Already covered in Phase 2 (token endpoint) and Phase 1 (pending endpoint).
Every 202 response must include the `AAuth` header.

### 6.3 Add AAuth Header to 401 Responses (Future)

When Keycloak acts as a resource (not typical), 401 responses should include
the AAuth header. This is primarily relevant for resource servers, not the auth server
itself, but the header utility should be available.

---

<a id="phase-7"></a>
## Phase 7: Metadata Endpoint Updates

### 7.1 Update Well-Known Path

**Current:** `/.well-known/aauth-issuer`
**Updated spec:** `/.well-known/aauth-issuer.json`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/wellknown/AAuthIssuerWellKnownProviderFactory.java`

Update the well-known URI to include `.json` suffix. Check how Keycloak registers
well-known providers — the factory likely specifies the path.

### 7.2 Update `AAuthIssuerMetadata`

**File:** `core/src/main/java/org/keycloak/representations/AAuthIssuerMetadata.java`

Change fields:

| Current Field | Updated Field | Notes |
|---------------|---------------|-------|
| `agentTokenEndpoint` | `token_endpoint` | Rename JSON property |
| `agentAuthEndpoint` | `interaction_endpoint` | Rename JSON property |
| `agentSigningAlgsSupported` | — | Remove |
| `requestTypesSupported` | — | Remove |
| `scopesSupported` | — | Remove |

Updated metadata shape:
```json
{
    "issuer": "https://auth.example",
    "token_endpoint": "https://auth.example/realms/myrealm/protocol/aauth/token",
    "interaction_endpoint": "https://auth.example/realms/myrealm/protocol/aauth/interact",
    "jwks_uri": "https://auth.example/realms/myrealm/protocol/aauth/certs"
}
```

### 7.3 Update `AAuthIssuerWellKnownProvider.getConfig()`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/wellknown/AAuthIssuerWellKnownProvider.java`

- Remove `getSupportedSigningAlgorithms()` call
- Remove `getSupportedScopes()` call
- Use new field names for endpoints
- Update endpoint URL paths if they change (e.g., `/agent/token` → `/token`)

### 7.4 Update Endpoint Paths in `AAuthProtocolService`

**File:** `services/src/main/java/org/keycloak/protocol/aauth/AAuthProtocolService.java`

Consider renaming paths to match spec conventions:

| Current | Updated |
|---------|---------|
| `/agent/token` | `/token` |
| `/agent/auth` | `/interact` |
| (new) | `/pending/{id}` |

```java
@Path("token")
public Object token() { ... }

@Path("interact")
public Object interact() { ... }

@Path("pending/{id}")
public Object pending(@PathParam("id") String id) { ... }
```

---

<a id="phase-8"></a>
## Phase 8: Token Response & Representation Cleanup

### 8.1 Update `AAuthTokenResponse`

**File:** `core/src/main/java/org/keycloak/representations/AAuthTokenResponse.java`

Remove fields:
- `refreshToken` — no more refresh tokens
- `requestToken` — replaced by 202 response with pending URL
- `tokenType` — not in updated spec responses

Keep fields:
- `authToken` → JSON: `"auth_token"`
- `expiresIn` → JSON: `"expires_in"`
- `error`, `errorDescription` — for error responses

Add fields for pending responses (or use a separate class):
- `status` → `"pending"`
- `location` → pending URL
- `require` → `"interaction"` or `"approval"`
- `code` → interaction code

**Recommendation:** Create a separate `AAuthPendingResponse` class for 202 bodies,
keep `AAuthTokenResponse` clean for 200 success responses.

### 8.2 Update `AAuthToken` (Auth Token JWT)

**File:** `core/src/main/java/org/keycloak/representations/AAuthToken.java`

The auth token structure is mostly unchanged. Verify these claims match the spec:

| Claim | Required | Notes |
|-------|----------|-------|
| `iss` | Yes | Auth server URL |
| `aud` | Yes | Resource URL (or agent URL for self-access) |
| `jti` | Yes | Unique token ID |
| `agent` | Yes | Agent identifier |
| `cnf` | Yes | Confirmation with jwk |
| `iat` | Yes | Issued at |
| `exp` | Yes | Expiration |
| `sub` | Conditional | User ID (at least one of sub/scope required) |
| `scope` | Conditional | Authorized scopes |
| `txn` | Conditional | Transaction ID from resource token |

**Add `txn` field** if not already present — the spec says when the resource token
contains a `txn` claim, it must be carried into the auth token.

### 8.3 Token Type Header

Current: `typ: "auth+jwt"` — this matches the spec. No change needed.

---

<a id="phase-9"></a>
## Phase 9: Approval Flow (Out-of-Band)

### 9.1 Concept

The updated spec distinguishes two kinds of deferred authorization:

- **`require=interaction`** — Agent must redirect user to interaction endpoint with code.
  This is the standard consent flow.
- **`require=approval`** — Auth server obtains approval directly (push notification,
  existing session, email) without agent involvement. Agent just polls.

### 9.2 Implementation in `AuthGrantType`

When consent is required, evaluate HOW it should be obtained:

```java
if (requiresConsent) {
    String requireType;
    if (canObtainApprovalDirectly(agentId, resourceId, scope)) {
        requireType = "approval";
        // No interaction code needed — agent just polls
    } else {
        requireType = "interaction";
        // Generate interaction code
    }

    AAuthPendingRequest pending = pendingStore.createPendingRequest(
        agentId, agentJkt, signatureScheme, resourceId, grantedScope,
        purpose, requireType);

    // Build 202 response (with or without code depending on requireType)
}
```

**`canObtainApprovalDirectly()`** — For initial implementation, this can always return
`false` (always use interaction). A future enhancement could check:
- Whether the user has an active session at the auth server
- Whether a push notification channel exists
- Whether an admin policy pre-approves certain agent+resource+scope combinations

### 9.3 Approval Completion

For the approval flow, the auth server itself must trigger completion of the pending
request when the user approves (e.g., via a separate admin/approval UI, push notification
response, etc.). This is an internal Keycloak mechanism — not an endpoint the agent calls.

For now, this can be stubbed out. The key requirement is that the pending endpoint
correctly handles `require=approval` in its 202 responses (no `code` field).

---

<a id="phase-10"></a>
## Phase 10: Clarification Chat (Optional)

This is a new optional feature. It can be deferred to a later iteration.

### 10.1 Concept

During consent, the user may ask a question about the agent's purpose. The auth server
delivers this question to the agent via the polling response, and the agent responds
via POST to the pending URL.

### 10.2 Polling Response with Clarification

When a clarification question is pending:
```json
{
    "status": "pending",
    "location": "/pending/abc123",
    "clarification": "Why do you need access to my calendar?"
}
```

### 10.3 Agent POST to Pending URL

```
POST /pending/abc123
Content-Type: application/json
{ "clarification_response": "I need to find available meeting times..." }
```

### 10.4 Implementation Sketch

- Add a `clarificationQuestion` field to `AAuthPendingRequest`
- The consent UI (shown to the user) includes a "Ask the agent" input
- When user submits a question, store it on the pending request
- The agent's next poll returns it in the 202 body
- Agent POSTs response to pending URL
- Pending endpoint handles POST by storing the response
- Auth server shows response to user, user can then approve/deny

**This requires bidirectional communication through the pending request store.** The
user's browser and the agent's polling are mediated by the stored pending request.

**Recommended: Defer to a future phase.** The core protocol works without it.

---

<a id="phase-11"></a>
## Phase 11: Token Endpoint Call Chaining (upstream_token)

### 11.1 Rename `ExchangeGrantType` Parameter

**File:** `services/src/main/java/org/keycloak/protocol/aauth/grants/ExchangeGrantType.java`

The updated spec uses `upstream_token` (not an auth token extracted from the JWT scheme).
The token request includes both `resource_token` and `upstream_token` in the JSON body:

```json
{
    "resource_token": "eyJ...",
    "upstream_token": "eyJ..."
}
```

Update the exchange handler to read `upstream_token` from the request body instead of
from the session attribute `aauth.upstream.auth.token`.

### 11.2 Remove Scope Narrowing Requirement

The updated spec (section 4.5.8) says:
> "The resulting authorization is not necessarily a subset of the upstream scopes — AS2
> may grant scopes that are independent of those in the upstream auth token."

The current `authorizeExchange()` enforces scope narrowing. **Remove this restriction.**
The upstream token provides provenance and user identity context, not a scope ceiling.

### 11.3 Integrate with 202 Flow

Call chaining can also result in 202 responses (interaction chaining, section 4.5.8.2).
When the downstream auth server requires user interaction, the resource chains the
interaction back. This should work naturally with the new pending/202 infrastructure.

---

<a id="phase-12"></a>
## Phase 12: Test Updates

### 12.1 Update Existing Tests

**Files:**
- `testsuite/.../AAuthDirectGrantTest.java` — Update to verify 202 responses
- `testsuite/.../AAuthRefreshTokenFlowTest.java` — Rewrite for expired token refresh
- `testsuite/.../AAuthUserConsentFlowTest.java` — Rewrite for interaction code + polling

### 12.2 New Tests

- `AAuthPendingEndpointTest.java` — Test polling lifecycle (202→200, 202→403, etc.)
- `AAuthInteractionCodeTest.java` — Test interaction code generation, lookup, expiry
- `AAuthTokenRefreshTest.java` — Test expired auth token refresh (replaces refresh token test)
- `AAuthMetadataTest.java` — Verify well-known metadata fields
- `AAuthApprovalFlowTest.java` — Test require=approval path (when implemented)

---

<a id="file-summary"></a>
## File-by-File Change Summary

### New Files

| File | Description |
|------|-------------|
| `storage/AAuthPendingRequest.java` | Pending request data model |
| `storage/AAuthPendingRequestStore.java` | Pending request lifecycle management |
| `endpoints/AAuthPendingEndpoint.java` | `GET/POST /pending/{id}` polling endpoint |
| `AAuthResponseHeader.java` | AAuth structured response header builder |
| `AAuthPendingResponse.java` (optional) | 202 response body representation |

### Modified Files

| File | Changes |
|------|---------|
| `AAuthProtocolService.java` | Add `/pending/{id}` path, rename `/agent/token`→`/token`, `/agent/auth`→`/interact` |
| `AAuthTokenEndpoint.java` | Accept JSON, auto-detect mode, remove `request_type` routing, add `Prefer: wait` parsing |
| `AuthGrantType.java` | Return 202+Location+AAuth header when consent needed, read `purpose` param |
| `AAuthAuthorizationEndpoint.java` | Rename to `AAuthInteractionEndpoint`, accept `code` param, complete pending request on consent, redirect to callback (no auth code) |
| `AAuthLoginProtocol.java` | Store interaction code instead of request_token in auth session |
| `AAuthTokenManager.java` | Remove `createRefreshToken()`, `validateRefreshToken()`; add `refreshFromExpiredAuthToken()` |
| `AAuthTokenResponse.java` | Remove `refreshToken`, `requestToken`, `tokenType` fields |
| `AAuthIssuerMetadata.java` | Rename fields to `token_endpoint`, `interaction_endpoint`; remove deprecated fields |
| `AAuthIssuerWellKnownProvider.java` | Update field population, remove deprecated metadata |
| `AAuthIssuerWellKnownProviderFactory.java` | Update well-known path to `aauth-issuer.json` |
| `ExchangeGrantType.java` | Read `upstream_token` from JSON body; remove scope narrowing |
| `AAuthSignatureFilter.java` | Verify GET requests are filtered for pending endpoint |
| `AAuthConsentBean.java` | Add `purpose` field |
| `login-aauth-grant.ftl` | Display `purpose`, update form action URL |
| `AAuthConfig.java` | Add any new config keys if needed |
| `AAuthToken.java` | Add `txn` field |

### Deleted Files

| File | Reason |
|------|--------|
| `grants/CodeGrantType.java` | Auth code flow eliminated |
| `grants/CodeGrantTypeFactory.java` | Auth code flow eliminated |
| `storage/AAuthAuthorizationCode.java` | Auth code flow eliminated |
| `grants/RefreshGrantType.java` | Refresh tokens eliminated |
| `grants/RefreshGrantTypeFactory.java` | Refresh tokens eliminated |
| `representations/AAuthRefreshToken.java` | Refresh tokens eliminated |
| `storage/AAuthRequestToken.java` | Replaced by AAuthPendingRequest |
| `storage/AAuthRequestTokenStore.java` | Replaced by AAuthPendingRequestStore |

### SPI Registration Updates

Remove from `META-INF/services/` (or equivalent registration):
- `CodeGrantTypeFactory` registration
- `RefreshGrantTypeFactory` registration

---

## Implementation Order

The recommended order minimizes breakage at each step:

1. **Phase 1** — Build the pending request infrastructure (store + endpoint). This is
   additive and doesn't break existing code.
2. **Phase 2** — Restructure token endpoint to return 202. This breaks the agent-side
   flow but the pending endpoint is ready to handle polls.
3. **Phase 3** — Rewrite interaction endpoint to use codes. After this, the full
   interaction+polling flow works end-to-end.
4. **Phase 4** — Delete auth code flow (now dead code).
5. **Phase 5** — Replace refresh tokens with expired auth token refresh.
6. **Phase 6** — Add AAuth response header to all relevant responses.
7. **Phase 7** — Update metadata.
8. **Phase 8** — Clean up representations.
9. **Phase 9-11** — Approval flow, clarification chat, call chaining updates.
10. **Phase 12** — Update and add tests.

---

## Open Questions / Decisions Needed

1. **Pending request store implementation:** `SingleUseObjectProvider` doesn't support
   atomic update. The remove-then-put pattern has a small race window. Is this acceptable
   for a prototype? (Answer: Yes for prototype, use distributed cache for production.)

2. **Long-polling (Prefer: wait):** Should we implement long-polling in the first pass
   or defer it? (Recommendation: Defer. Return 202 immediately, let agent poll.)

3. **Endpoint path naming:** Should we change `/agent/token` → `/token` and
   `/agent/auth` → `/interact`? Or keep the current paths for backward compatibility?
   (Recommendation: Change paths to match spec conventions. The spec URLs in metadata
   are what agents use.)

4. **JSON vs form-encoded:** The spec uses JSON request bodies. Should we drop
   form-encoded entirely or support both? (Recommendation: JSON primary, drop form.)

5. **Interaction code format:** The spec says unreserved URI characters
   (A-Z a-z 0-9 - . _ ~). What length? (Recommendation: 8 uppercase alphanumeric
   characters, e.g., "ABCD1234", matching the spec examples.)

6. **ExchangeGrantType integration:** Should exchange also support 202/polling for
   interaction chaining? (Recommendation: Yes, in Phase 11, since the pending
   infrastructure from Phase 1 supports it.)
