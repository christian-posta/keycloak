# AAuth User Consent Configuration (Phase 1)

This document describes how to configure which scopes require user consent in the AAuth protocol. When an agent requests an auth token, the auth server evaluates the requested scopes and decides whether to return a `request_token` (requiring user consent) or an `auth_token` (direct grant).

## Overview

In the AAuth protocol, when an agent makes an auth request (`request_type=auth`), the auth server evaluates the requested scopes against configured policies to determine if user consent is required:

- **If user consent is required**: The server returns a `request_token`, which the agent uses to redirect the user to the authorization endpoint for authentication and consent.
- **If user consent is not required**: The server returns an `auth_token` directly (machine-to-machine flow).

This decision is configurable via realm attributes, allowing administrators to control which scopes trigger the user consent flow.

## Realm Attributes

### `aauth.consent.required.scopes`

A JSON array of scope names that require user consent. Any requested scope that exactly matches an entry in this list will trigger the user consent flow.

**Example:**
```json
["openid", "profile", "email", "calendar.read"]
```

### `aauth.consent.required.scope.prefixes`

A JSON array of scope name prefixes. Any requested scope whose name starts with one of these prefixes will trigger the user consent flow.

**Example:**
```json
["user.", "profile.", "email."]
```

This is useful for scopes that follow a naming pattern, such as `user.preferences`, `user.settings`, `profile.display`, etc.

## Default Behavior

When both `aauth.consent.required.scopes` and `aauth.consent.required.scope.prefixes` are **not set** (missing or empty), the system uses backward-compatible defaults:

- **Exact scope matches**: `openid`, `profile`, `email`
- **Scope prefixes**: `user.`, `profile.`, `email.`

This ensures that existing deployments continue to work without configuration changes.

**Important**: Once you set either attribute (even to an empty array `[]`), the system will use **only** your configured lists and will not apply the defaults. To restore default behavior, remove the attributes entirely.

## Configuring via REST API

The easiest way to configure these attributes is using the provided script:

```bash
./scripts/set_aauth_consent_attributes.sh [BASE_URL] [REALM_NAME] [ADMIN_USER] [ADMIN_PASSWORD]
```

**Example:**
```bash
./scripts/set_aauth_consent_attributes.sh http://localhost:8080 aauth-test admin admin
```

### Manual Configuration via REST API

You can also configure these attributes manually using the Keycloak Admin REST API:

**Step 1: Get Admin Token**
```bash
TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
```

**Step 2: Get Current Realm**
```bash
curl -s -X GET "http://localhost:8080/admin/realms/aauth-test" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" > realm.json
```

**Step 3: Update Realm Attributes**

Edit `realm.json` to add or modify the `attributes` section:

```json
{
  "realm": "aauth-test",
  "attributes": {
    "aauth.consent.required.scopes": "[\"openid\",\"profile\",\"email\",\"calendar.read\"]",
    "aauth.consent.required.scope.prefixes": "[\"user.\",\"profile.\",\"email.\"]"
  }
}
```

**Step 4: Update Realm**
```bash
curl -X PUT "http://localhost:8080/admin/realms/aauth-test" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d @realm.json
```

**Note**: When updating realm attributes via REST API, you must include the **entire realm representation** (GET, modify, PUT). The PUT operation replaces the entire realm configuration, so be careful not to lose other settings.

## Examples

### Example 1: Custom User Scopes Only

Require consent only for scopes starting with `user.`:

```json
{
  "attributes": {
    "aauth.consent.required.scope.prefixes": "[\"user.\"]"
  }
}
```

**Result:**
- `scope=user.preferences` → `request_token` (requires consent)
- `scope=profile` → `auth_token` (direct grant)
- `scope=data.read` → `auth_token` (direct grant)

### Example 2: Specific API Scopes

Require consent for specific API scopes:

```json
{
  "attributes": {
    "aauth.consent.required.scopes": "[\"calendar.read\",\"calendar.write\",\"contacts.read\"]"
  }
}
```

**Result:**
- `scope=calendar.read` → `request_token` (requires consent)
- `scope=calendar.write` → `request_token` (requires consent)
- `scope=data.read` → `auth_token` (direct grant)

### Example 3: Mixed Configuration

Use both exact matches and prefixes:

```json
{
  "attributes": {
    "aauth.consent.required.scopes": "[\"openid\",\"profile\",\"email\"]",
    "aauth.consent.required.scope.prefixes": "[\"user.\",\"api.write\"]"
  }
}
```

**Result:**
- `scope=openid` → `request_token` (exact match)
- `scope=user.preferences` → `request_token` (prefix match)
- `scope=api.write.data` → `request_token` (prefix match)
- `scope=data.read` → `auth_token` (no match)

### Example 4: Disable Default Behavior

To disable all default consent requirements and only require consent for explicitly configured scopes, set empty arrays:

```json
{
  "attributes": {
    "aauth.consent.required.scopes": "[]",
    "aauth.consent.required.scope.prefixes": "[]"
  }
}
```

**Result:** All scopes will be direct grant (no consent) unless you add specific entries to the lists.

## Testing

After configuring the consent attributes, test the behavior using the AAuth test client:

**Test with consent-required scope:**
```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --scope "profile email" \
  --redirect-uri "http://localhost:9000/callback"
```

This should return a `request_token` if `profile` or `email` are in your consent-required scopes.

**Test with non-consent scope:**
```bash
python scripts/aauth_test_client.py \
  --base-url http://localhost:8080 \
  --realm aauth-test \
  --scope "data.read" \
  --redirect-uri "http://localhost:9000/callback"
```

This should return an `auth_token` directly if `data.read` is not in your consent-required scopes.

## Post-Consent Flow: What Happens When User Grants Consent

When the user clicks **Allow** on the consent screen, the following sequence occurs:

### 1. Keycloak Redirects to Agent's Callback

Keycloak redirects the **browser** to the `redirect_uri` (the agent's callback URL) with the authorization code and state:

```
HTTP 303 See Other
Location: {redirect_uri}?code={authorization_code}&state={state}
```

**Critical**: `redirect_uri` MUST be the **agent's** callback URL (e.g. `http://backend.localhost:8000/auth/aauth/callback`), NOT the frontend UI URL. The agent needs to receive the code because only the agent can exchange it (requires the agent's signing key).

### 2. Agent Receives the Code

The agent's callback endpoint receives the HTTP GET with `code` and `state` query parameters. The agent must:

1. **Extract** `code` and `state` from the URL
2. **Exchange** the code for tokens by making a signed POST to Keycloak's `/agent/token` endpoint:
   ```
   POST /realms/{realm}/protocol/aauth/agent/token
   Content-Type: application/x-www-form-urlencoded
   Signature-Key: ... (agent's signing key)
   Signature: ... (RFC 9421 signature)

   request_type=code&code={code}&redirect_uri={same_redirect_uri}&state={state}
   ```
3. **Store** the returned `auth_token` and `refresh_token` (e.g. in session, secure cookie, or pass to frontend via secure channel)
4. **Redirect** the user to the frontend UI with a **success indicator** (e.g. `?success=1` or session cookie)

### 3. Frontend UI Expectations

The **frontend** (e.g. `http://localhost:3050`) should **NOT** expect to receive `code` or `state`. Those are consumed by the agent's callback. Instead:

- **Success case**: The agent redirects to the frontend with a success indicator (e.g. `?aauth_success=1` or the agent sets a session cookie). The frontend should detect this and show "Authorization complete" or proceed to the next step.
- **Error case**: If the agent encounters an error (e.g. code exchange failed), the agent should redirect to the frontend with error params (e.g. `?aauth_error=1&error=...&error_description=...`).

**Common mistake**: Using the frontend URL as `redirect_uri`. If the frontend receives the redirect, it will see `code` and `state` in the URL—but the frontend cannot exchange the code (it doesn't have the agent's signing key). The frontend would show "missing code or state" if it expects the agent to have already exchanged them and passed tokens another way.

**Correct architecture**:
```
User → Keycloak consent → Keycloak redirects to AGENT callback (8000) with code
       → Agent exchanges code for tokens
       → Agent redirects to FRONTEND (3050) with success/error
       → Frontend shows result (no code/state needed)
```

### 4. Agent Callback Implementation Checklist

Your agent's `/auth/aauth/callback` (or equivalent) must:

- [ ] Handle GET requests with `code` and `state` query params
- [ ] Immediately exchange the code via signed POST to `/agent/token`
- [ ] Use the same `redirect_uri` in the exchange that was used in the original auth request
- [ ] On success: redirect user to frontend with success (e.g. `{frontend_url}?aauth_success=1`)
- [ ] On error: redirect user to frontend with error (e.g. `{frontend_url}?aauth_error=1&error=...`)

## Debugging: Consent Screen Not Showing

Enable AAuth logging to trace the consent flow:

```bash
# CLI - INFO level shows consent flow milestones
./kc.sh start --log-level=org.keycloak.protocol.aauth:INFO

# CLI - DEBUG level for verbose output
./kc.sh start --log-level=org.keycloak.protocol.aauth:DEBUG
```

**Key log messages to look for:**
- `AAuth auth grant: scope=X, requiresConsent=true` → request_token was issued (agent must redirect user to /agent/auth)
- `AAuth auth grant: scope=X, requiresConsent=false` → auth_token issued directly (no consent flow)
- `AAuth consent flow: User authenticated, showing consent screen` → Consent page should render
- `AAuth consent flow: Failed to render consent screen` → Template/theme error (check stack trace)

**Common issues:**
1. **Getting auth_token instead of request_token?** Your scope may not require consent. Use `profile`, `email`, or `openid` (default consent-required) or configure realm attributes.
2. **Agent not redirecting?** After receiving request_token, the agent must redirect the user to `{base}/realms/{realm}/protocol/aauth/agent/auth?request_token=...&redirect_uri=...&state=...`
3. **Missing redirect_uri?** It's required when requesting consent-required scopes.
4. **Frontend shows "missing code or state" after consent?** The frontend is likely the `redirect_uri` target. It should be the **agent's** callback URL instead. Keycloak redirects to `redirect_uri` with code and state—the agent must receive them, exchange the code for tokens, then redirect the user to the frontend with a success indicator (not code/state).

## Related Documentation

- [AAuth Phase 3 Manual Testing Guide](AAUTH_PHASE3_MANUAL_TESTING.md) - Testing the user consent flow
- [AAuth Phase 4 Manual Testing Guide](AAUTH_PHASE4_MANUAL_TESTING.md) - Advanced testing scenarios
