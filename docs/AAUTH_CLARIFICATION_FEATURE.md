# AAuth Clarification Chat Feature

The clarification chat feature allows a user viewing the consent screen to ask the agent a question before making an authorization decision. The agent answers asynchronously, and the answer is displayed back to the user.

## Overview

When certain scopes are requested, the consent screen includes a text box where the user can type a question. The agent receives the question on its next poll and posts a response. The user then sees the answer and decides to accept or deny.

## Flow Diagram

```
Agent                  Keycloak Auth Server          User Browser
  |                           |                           |
  |-- POST /token ----------->|                           |
  |   (scope: clarify.*)      |                           |
  |<-- 202 + Location --------|                           |
  |                           |                           |
  |-- GET /pending/{id} ----->|                           |
  |<-- 202 pending ----------->                           |
  |                           |                           |
  |                           |<-- GET /interact?code=XXXX|
  |                           |--- Consent+Clarify UI --->|
  |                           |                           |
  |                           |<-- POST /interact/clarify |
  |                           |    {clarification_question}
  |                           |                           |
  |-- GET /pending/{id} ----->|                           |
  |<-- 202 + clarification ---|                           |
  |                           |                           |
  |-- POST /pending/{id} ---->|                           |
  |   {clarification_response}|                           |
  |<-- 200 clarification_received                         |
  |                           |                           |
  |                           |<-- GET /interact?code=XXXX|
  |                           |--- Shows Q&A + buttons -->|
  |                           |                           |
  |                           |<-- POST /interact/consent |
  |                           |    {accept}               |
  |                           |                           |
  |-- GET /pending/{id} ----->|                           |
  |<-- 200 + auth_token ------|                           |
```

## Configuration

### Realm Attribute: `aauth.clarification.required.scopes`

Set this realm attribute to a JSON array of scope names that trigger clarification mode:

```json
["clarify.read", "clarify.write", "sensitive.data"]
```

Any auth request that includes one or more of these scopes will display the clarification chat UI on the consent screen.

The `purpose` field (spec §14) is also shown on the consent screen and is especially useful with clarification — it gives the user context about why the agent is asking before they type their question.

**Example using Keycloak Admin API:**
```bash
curl -X PUT \
  http://localhost:8080/admin/realms/myrealm \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "aauth.clarification.required.scopes": "[\"clarify.read\",\"clarify.write\"]"
    }
  }'
```

## Agent Requirements

The agent must declare `clarification_supported: true` in its well-known metadata (`/.well-known/aauth-agent.json`):

```json
{
  "agent": "https://my-agent.example.com",
  "jwks_uri": "https://my-agent.example.com/.well-known/jwks.json",
  "client_name": "My AI Agent",
  "clarification_supported": true
}
```

> **Note**: Currently, Keycloak enables clarification mode based solely on scope configuration. Agent metadata is not checked at request time. This may be enforced in a future version.

## Agent Implementation Guide

### Step 1: Initial Token Request

Post a JSON body to the token endpoint (signed with HTTPSig). The server infers the request type from the parameters — `scope` without `resource_token` means the agent is the audience (self-access / SSO). `resource_token` means access to a separate resource.

```http
POST /realms/{realm}/protocol/aauth/token
Host: keycloak.example.com
Content-Type: application/json
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "scope": "clarify.read",
  "purpose": "Summarize the Q3 revenue spreadsheet you shared yesterday"
}
```

Or, when the agent is accessing a separate resource (using a resource token it received from the resource's 401 challenge):

```http
POST /realms/{realm}/protocol/aauth/token
Host: keycloak.example.com
Content-Type: application/json
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "resource_token": "eyJhbGc...",
  "purpose": "Summarize the Q3 revenue spreadsheet you shared yesterday"
}
```

**Response** (202 Accepted):
```http
HTTP/1.1 202 Accepted
Location: https://keycloak.example.com/realms/{realm}/protocol/aauth/pending/abc-123
Retry-After: 0
Cache-Control: no-store
AAuth: require=interaction; code="ABCD1234"
Content-Type: application/json

{
  "status": "pending",
  "location": "https://keycloak.example.com/realms/{realm}/protocol/aauth/pending/abc-123",
  "require": "interaction",
  "code": "ABCD1234"
}
```

### Step 2: Direct User to Interaction URL

The agent constructs the interaction URL using the `interaction_endpoint` from the auth server's metadata (`/.well-known/aauth-issuer.json`) and appends the `code` and optional `callback`:

```
{interaction_endpoint}?code=ABCD1234&callback=https%3A%2F%2Fmy-agent.example.com%2Fcallback
```

For example:
```
https://keycloak.example.com/realms/{realm}/protocol/aauth/interact?code=ABCD1234&callback=https%3A%2F%2Fmy-agent.example.com%2Fcallback
```

The user will see the consent screen with a clarification text box.

### Step 3: Poll for Clarification Question

Poll `GET /pending/{id}` with HTTPSig on every request, using `Prefer: wait=N` to hold the connection open:

```http
GET /realms/{realm}/protocol/aauth/pending/abc-123
Host: keycloak.example.com
Prefer: wait=45
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."
```

**While pending (no clarification yet):**
```json
{
  "status": "pending",
  "location": "...",
  "require": "interaction",
  "code": "ABCD1234"
}
```

**Once user submits a clarification question** (status becomes `awaiting_clarification`):
```json
{
  "status": "awaiting_clarification",
  "location": "...",
  "require": "interaction",
  "code": "ABCD1234",
  "clarification": "What specific files will you access?"
}
```

### Step 4: Post Clarification Response

When you receive a `clarification` field, POST your response to the same pending URL — this is the only case where the agent sends a non-GET request to a pending URL (per spec §10.3):

```http
POST /realms/{realm}/protocol/aauth/pending/abc-123
Host: keycloak.example.com
Content-Type: application/json
Signature-Input: sig=("@method" "@authority" "@path" "signature-key");created=1730217600
Signature: sig=:...signature bytes...:
Signature-Key: sig=jwt;jwt="eyJhbGc..."

{
  "clarification_response": "I will only access files in the /reports directory that are owned by the requesting user."
}
```

**Response** (200 OK):
```json
{
  "status": "clarification_received"
}
```

### Step 5: User Makes Decision

After your response is stored, the user refreshes the consent page and sees your answer alongside their question. They then accept or deny the authorization.

### Step 6: Poll for Final Result

Continue polling as normal:

**Approved** (200 OK):
```json
{
  "auth_token": "eyJhbGci...",
  "expires_in": 300
}
```

**Denied** (403 Forbidden):
```json
{
  "error": "access_denied"
}
```

## Complete Agent Example (Python pseudocode)

```python
import httpx

TOKEN_ENDPOINT = "https://keycloak.example.com/realms/{realm}/protocol/aauth/token"
INTERACTION_ENDPOINT = "https://keycloak.example.com/realms/{realm}/protocol/aauth/interact"

def request_auth_token(scope: str, purpose: str, callback_url: str) -> str:
    """Request an auth token; handle 202 deferred response with clarification."""

    # Step 1: POST JSON to token endpoint (signed with HTTPSig)
    resp = signed_post(TOKEN_ENDPOINT,
        json={"scope": scope, "purpose": purpose},
        headers={"Prefer": "wait=45"})

    if resp.status_code == 200:
        # Direct grant — no user interaction needed
        return resp.json()["auth_token"]

    if resp.status_code == 202:
        body = resp.json()
        pending_url = body["location"]
        code = body.get("code")

        # Step 2: Direct user to interaction endpoint
        interact_url = f"{INTERACTION_ENDPOINT}?code={code}&callback={callback_url}"
        print(f"Direct user to: {interact_url}")

        # Step 3-6: Poll and handle clarification
        return poll_with_clarification(pending_url)

    raise RuntimeError(f"Unexpected status: {resp.status_code} {resp.text}")


def poll_with_clarification(pending_url: str) -> str:
    """Poll a pending URL, handling clarification questions if they arrive."""
    while True:
        # Always use GET with Prefer: wait; always sign the request
        resp = signed_get(pending_url, headers={"Prefer": "wait=45"})

        if resp.status_code == 200:
            return resp.json()["auth_token"]

        if resp.status_code == 202:
            body = resp.json()

            if body.get("status") == "awaiting_clarification":
                question = body["clarification"]
                print(f"User asks: {question}")
                answer = generate_answer(question)  # Your agent logic here

                # POST the answer to the same pending URL (only non-GET allowed on pending URLs)
                signed_post(pending_url,
                    json={"clarification_response": answer})
                print("Answer sent, waiting for user decision...")

            # Continue polling
            continue

        if resp.status_code == 403:
            raise PermissionError("User denied the request")
        if resp.status_code == 408:
            raise TimeoutError("Request expired — start over with a fresh token request")
        if resp.status_code == 410:
            raise RuntimeError("Pending URL is gone — do not retry")
```

## Security Considerations

1. **Agent signing**: All `GET` and `POST` requests to `/pending/{id}` must be signed with HTTPSig. The server verifies the agent's JKT matches the original requester.

2. **One-time delivery**: After the auth token is delivered (200 OK), the pending request is consumed. Subsequent polls return 404.

3. **Expiration**: Pending requests expire after 10 minutes. If the clarification exchange takes too long, the request expires and the agent must start over.

4. **Clarification is optional for the user**: The user can accept or deny without asking a clarification question. The clarification chat is a UI affordance only.

## Disabling Clarification for a Realm

Set the `aauth.clarification.required.scopes` attribute to an empty array `[]` or remove it entirely. No scopes will trigger clarification mode.
