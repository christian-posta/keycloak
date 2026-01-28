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

## Related Documentation

- [AAuth Phase 3 Manual Testing Guide](AAUTH_PHASE3_MANUAL_TESTING.md) - Testing the user consent flow
- [AAuth Phase 4 Manual Testing Guide](AAUTH_PHASE4_MANUAL_TESTING.md) - Advanced testing scenarios
