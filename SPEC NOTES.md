
## The auth server decides; the agent learns from the response

Per SPEC.md, the **auth server** decides whether user consent is needed. The agent does **not** need to know this in advance. It always calls the same token endpoint; the response body tells it what to do next.

### 1. Agent always starts the same way

The agent requests an auth token with a single request type:

- **Section 9.3 (Agent Auth Request):**  
  The agent sends a signed request to the auth server’s `agent_token_endpoint` with **`request_type=auth`**, plus either `resource_token`, `scope`, or `auth_request_url`, and `redirect_uri`.

There is no separate “user-delegated” request type for this first step. The same `request_type=auth` is used whether the outcome will be a direct grant or user consent.

### 2. Auth server decides based on policy

**Section 9.4 (Auth Response)** says:

> “The auth server validates the request and **responds based on policy**.”

So the server evaluates the request (and its own policy, resource, user context, etc.) and picks one of two response shapes.

### 3. Two possible responses — and how the agent knows

**Section 9.4** defines exactly two outcomes:

1. **Direct grant (no user flow)**  
   Response contains `auth_token` (and typically `expires_in`, `refresh_token`). The agent uses the token; no user step.

2. **User consent required (user-delegated flow)**  
   Response contains **`request_token`** (and e.g. `expires_in`), and **no** `auth_token`.

So the agent infers “user-delegated flow” solely from seeing **`request_token`** in the response.

**Section 9.5 (User Consent Flow)** states that explicitly:

> “**If the auth server responds with a `request_token`** (indicating user consent is required), the agent directs the user to the `agent_auth_endpoint` for authentication and authorization.”

So:

- **Presence of `request_token`** → start the user consent flow (redirect user to `agent_auth_endpoint` with that token).
- **Presence of `auth_token`** → no user step; use the token.

### 4. “Request token” vs “request code”

The SPEC uses **request_token**, not “request code,” for this:

- **Section 2.1:**  
  “**request token**: An opaque string issued by the auth server representing a **pending authorization request**. The agent uses this token at the `agent_auth_endpoint` to **initiate user consent**.”

So the “thing” that tells the agent “run the user-delegated flow” is the **`request_token`** in the 200 JSON body of the auth response, not a code in the URL or a separate “request code” parameter name.

### 5. No requirement that the agent knows ahead of time

There is no spec language saying the agent must know in advance that user delegation is needed. The flow is:

1. Agent needs access → calls `agent_token_endpoint` with `request_type=auth` (+ resource_token/scope/auth_request_url, redirect_uri).
2. Auth server evaluates and returns either:
   - `auth_token` (+ refresh etc.) → done; or  
   - `request_token` → user consent required.
3. **Only when** the agent sees `request_token` does it start the user flow (redirect to `agent_auth_endpoint` with that token, then later exchange the authorization `code` for tokens).

So: the auth server effectively says “this request needs user consent” by **sending back a `request_token`** instead of an `auth_token`. That is how the user-delegated flow is started — by the server’s choice of response type, not by the agent choosing a different initial request.