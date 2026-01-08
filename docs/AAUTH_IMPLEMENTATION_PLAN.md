---
name: AAuth Auth Server Implementation
overview: Implement the complete AAuth auth server specification in Keycloak, enabling agents to authenticate and obtain authorization tokens using HTTP Message Signing. The implementation will coexist with existing OAuth/OIDC flows and be built iteratively across 5 phases.
todos:
  - id: phase1-httpsig
    content: "Phase 1: Implement HTTP Message Signing verification infrastructure - library integration, signature schemes, metadata fetchers, request filter, token validators"
    status: pending
  - id: phase2-core
    content: "Phase 2: Implement core protocol endpoints - well-known metadata, agent token endpoint, auth grant type, AAuth token manager, direct grant flow"
    status: pending
    dependencies:
      - phase1-httpsig
  - id: phase3-consent
    content: "Phase 3: Implement user consent flow - agent auth endpoint, request token storage, code grant type, consent screen integration"
    status: pending
    dependencies:
      - phase2-core
  - id: phase4-exchange
    content: "Phase 4: Implement token exchange and refresh - exchange grant type, refresh grant type, actor claim support, federation trust management"
    status: pending
    dependencies:
      - phase3-consent
  - id: phase5-advanced
    content: "Phase 5: Advanced features and polish - token encryption, auth request documents, agent-aware policies, nonce replay prevention, admin UI, documentation"
    status: pending
    dependencies:
      - phase4-exchange
---

# AAuth Auth Server Implementation Plan

## Architecture Overview

The implementation follows Keycloak's SPI-based architecture to ensure coexistence with OAuth/OIDC:

- **New Protocol Path**: `/protocol/aauth/` (parallel to `/protocol/openid-connect/`)
- **HTTP Message Signing**: RFC 9421 signature verification for all agent requests
- **Four Grant Types**: `request_type=auth`, `code`, `exchange`, `refresh` via `OAuth2GrantType` SPI
- **Well-Known Metadata**: `/.well-known/aauth-issuer` via `WellKnownProvider` SPI
- **Token Format**: Extended `AccessToken` with `agent`, `cnf.jwk`, `typ="auth+jwt"` claims

## Phase 1: HTTP Message Signing Foundation

**Goal**: Implement HTTP Message Signing (HTTPSig) verification infrastructure

**Deliverables**:
1. HTTP Message Signing library integration (RFC 9421)
2. Signature verification filter/interceptor
3. Support for all four signature schemes
4. Key discovery and caching mechanisms

**Key Components**:

### 1.1 HTTPSig Library Integration
- **Location**: New module `services/src/main/java/org/keycloak/protocol/aauth/signing/`
- **Files**:
  - `HTTPSigVerifier.java` - Main signature verification logic
  - `SignatureKeyParser.java` - Parse `Signature-Key` header (RFC 8941 structured fields)
  - `SignatureBaseBuilder.java` - Construct signature base string per AAuth profile
- **Dependencies**: Add HTTP Signature library (e.g., `http-signature-utils` or custom implementation)

### 1.2 Signature Scheme Handlers
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/signing/schemes/`
- **Files**:
  - `HeaderWebKeyScheme.java` - `scheme=hwk` (extract key from header)
  - `JWKSUriScheme.java` - `scheme=jwks_uri` (fetch agent metadata + JWKS)
  - `X509Scheme.java` - `scheme=x509` (fetch and validate certificate)
  - `JWTScheme.java` - `scheme=jwt` (validate agent/auth token, extract `cnf.jwk`)
- **Pattern**: Similar to `ClientAsymmetricSignatureVerifierContext` but for HTTP signatures

### 1.3 Agent/Resource Metadata Fetchers
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/metadata/`
- **Files**:
  - `AgentMetadataFetcher.java` - Fetch `/.well-known/aauth-agent` from agent URLs
  - `ResourceMetadataFetcher.java` - Fetch `/.well-known/aauth-resource` from resource URLs
  - `MetadataCache.java` - Cache metadata with TTL (similar to `PublicKeyStorageManager`)
- **Pattern**: Similar to how Keycloak fetches OIDC provider metadata in `AbstractOAuth2IdentityProvider`

### 1.4 Request Filter/Interceptor
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/filters/`
- **Files**:
  - `AAuthSignatureFilter.java` - JAX-RS `ContainerRequestFilter` to verify signatures
  - **Pattern**: Similar to `KeycloakSecurityHeadersFilter` but for signature verification
  - **Priority**: Must run before authentication flow, after SSL check
- **Integration**: Register via `@Provider` annotation or SPI

### 1.5 Agent Token Validator
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/tokens/`
- **Files**:
  - `AgentTokenValidator.java` - Validate `agent+jwt` tokens
  - **Pattern**: Similar to `JWTClientValidator` but for agent tokens
  - **Validations**: `typ="agent+jwt"`, signature, `iss`, `sub`, `exp`, `cnf.jwk`

### 1.6 Resource Token Validator
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/tokens/`
- **Files**:
  - `ResourceTokenValidator.java` - Validate `resource+jwt` tokens
  - **Validations**: `typ="resource+jwt"`, signature, `iss`, `aud`, `agent`, `agent_jkt`, `exp`

**Testing**: Unit tests for each scheme handler, integration tests for signature verification

---

## Phase 2: Core Protocol Endpoints & Token Issuance

**Goal**: Implement basic AAuth endpoints and direct grant flow

**Deliverables**:
1. Well-known metadata endpoint
2. Agent token endpoint with `request_type=auth`
3. Auth token issuance with AAuth format
4. Basic direct grant (no user consent)

**Key Components**:

### 2.1 Well-Known Metadata Provider
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/wellknown/`
- **Files**:
  - `AAuthIssuerWellKnownProvider.java` - Implements `WellKnownProvider`
  - `AAuthIssuerWellKnownProviderFactory.java` - Implements `WellKnownProviderFactory`
  - `AAuthIssuerMetadata.java` - JSON representation class
- **Pattern**: Follow `OIDCWellKnownProvider` and `OIDCWellKnownProviderFactory`
- **Endpoint**: `/.well-known/aauth-issuer`
- **Metadata Fields**: `issuer`, `jwks_uri`, `agent_token_endpoint`, `agent_auth_endpoint`, `agent_signing_algs_supported`, `request_types_supported`
- **Registration**: Add to `META-INF/services/org.keycloak.wellknown.WellKnownProviderFactory`

### 2.2 AAuth Protocol Service
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/AAuthProtocolService.java`
- **Pattern**: Similar to `OIDCLoginProtocolService`
- **Endpoints**:
  - `@Path("agent/token")` → `AAuthTokenEndpoint`
  - `@Path("agent/auth")` → `AAuthAuthorizationEndpoint` (Phase 3)
  - `@Path("certs")` → JWKS endpoint (reuse existing or create new)
- **Registration**: Add route in `RealmsResource` or create new protocol resource

### 2.3 Agent Token Endpoint
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/endpoints/AAuthTokenEndpoint.java`
- **Pattern**: Similar to `TokenEndpoint` but for AAuth protocol
- **Responsibilities**:
  - Verify HTTP Message Signature (via filter from Phase 1)
  - Extract agent identity from signature
  - Route to appropriate grant type based on `request_type` parameter
  - Handle CORS (similar to existing token endpoint)

### 2.4 Auth Grant Type (`request_type=auth`)
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/grants/AuthGrantType.java`
- **Factory**: `AuthGrantTypeFactory.java`
- **Pattern**: Implements `OAuth2GrantType` SPI (like `AuthorizationCodeGrantType`)
- **Flow**:
  1. Validate `resource_token` OR `scope`/`auth_request_url` (agent as resource)
  2. If `resource_token`: Validate via `ResourceTokenValidator`
  3. Extract agent identity from HTTPSig signature
  4. Evaluate authorization policy
  5. Return `auth_token` (direct grant) OR `request_token` (user consent needed - Phase 3)
- **Registration**: Add to `META-INF/services/org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory`

### 2.5 AAuth Token Manager
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/AAuthTokenManager.java`
- **Pattern**: Extends or wraps `TokenManager` for AAuth-specific token creation
- **Responsibilities**:
  - Create auth tokens with `typ="auth+jwt"` header
  - Add `agent` claim (HTTPS URL)
  - Add `agent_delegate` claim (if present in agent token)
  - Add `cnf.jwk` claim (proof-of-possession key from signature)
  - Add `act` claim (for token exchange - Phase 4)
  - Sign with Keycloak's signing key
- **Token Format**: Extend `AccessToken` or create `AAuthToken` class

### 2.6 Token Response Format
- **Location**: `core/src/main/java/org/keycloak/representations/AAuthTokenResponse.java`
- **Pattern**: Similar to `AccessTokenResponse` but with AAuth-specific fields
- **Fields**: `auth_token`, `expires_in`, `refresh_token`, `request_token` (conditional)

**Testing**: Integration tests for direct grant flow, token format validation

---

## Phase 3: User Consent Flow

**Goal**: Implement interactive user authentication and consent

**Deliverables**:
1. Agent auth endpoint (user-facing)
2. Authorization code grant (`request_type=code`)
3. Request token handling
4. User consent UI integration

**Key Components**:

### 3.1 Agent Auth Endpoint
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/endpoints/AAuthAuthorizationEndpoint.java`
- **Pattern**: Similar to `AuthorizationEndpoint` but for AAuth
- **Flow**:
  1. Receive `request_token` parameter
  2. Validate `request_token` (lookup pending auth request)
  3. If user not authenticated: redirect to Keycloak login
  4. Display consent screen (agent identity, resource, scopes)
  5. Generate authorization code bound to `request_token`
  6. Redirect back to agent's `redirect_uri` with code
- **Integration**: Reuse existing authentication flows and consent screens

### 3.2 Request Token Storage
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/storage/`
- **Files**:
  - `RequestTokenStore.java` - Store pending auth requests
  - **Storage**: Use Keycloak's session storage or create new storage provider
  - **Data**: Agent identity, resource token/scope, redirect_uri, expiration
- **Pattern**: Similar to how `OAuth2Code` stores authorization codes

### 3.3 Code Grant Type (`request_type=code`)
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/grants/CodeGrantType.java`
- **Factory**: `CodeGrantTypeFactory.java`
- **Pattern**: Similar to `AuthorizationCodeGrantType` but validates agent signature
- **Flow**:
  1. Extract authorization code from request
  2. Validate code and lookup `request_token`
  3. Verify agent signature matches original request
  4. Verify `redirect_uri` matches
  5. Issue `auth_token` and `refresh_token`
- **Registration**: Add to grant type SPI

### 3.4 Consent Screen Integration
- **Location**: `themes/base/account/src/main/resources/theme/base/account/aauth-consent.ftl`
- **Pattern**: Similar to existing OAuth consent screen
- **Display**: Agent identity (from metadata), resource, scopes, user info
- **Integration**: Extend existing consent flow to support AAuth requests

**Testing**: End-to-end tests for user consent flow, authorization code validation

---

## Phase 4: Token Exchange & Refresh

**Goal**: Implement multi-hop resource access and token refresh

**Deliverables**:
1. Token exchange grant (`request_type=exchange`)
2. Refresh grant (`request_type=refresh`)
3. Actor (`act`) claim for delegation chains
4. Refresh token binding to agent identity

**Key Components**:

### 4.1 Exchange Grant Type (`request_type=exchange`)
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/grants/ExchangeGrantType.java`
- **Factory**: `ExchangeGrantTypeFactory.java`
- **Pattern**: Similar to existing `TokenExchangeGrantType` but with AAuth validation
- **Flow**:
  1. Extract `resource_token` from request
  2. Validate `resource_token` via `ResourceTokenValidator`
  3. Extract upstream `auth_token` from `Signature-Key` header (`scheme=jwt`)
  4. Validate upstream token signature (from upstream auth server)
  5. Establish trust relationship with upstream auth server (federation)
  6. Authorize exchange (scope narrowing, delegation chain validation)
  7. Issue new `auth_token` with `act` claim showing delegation chain
- **Actor Claim**: Include upstream agent, `agent_delegate`, `sub` in `act` claim

### 4.2 Refresh Grant Type (`request_type=refresh`)
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/grants/RefreshGrantType.java`
- **Factory**: `RefreshGrantTypeFactory.java`
- **Pattern**: Similar to `RefreshTokenGrantType` but validates agent signature
- **Flow**:
  1. Extract `refresh_token` from request
  2. Validate refresh token (signature, expiration, binding)
  3. Verify agent signature matches token's bound agent
  4. Verify `agent_delegate` (`sub`) matches if present
  5. Issue new `auth_token` (refresh token remains valid, no rotation)
- **Token Binding**: Refresh tokens bound to `agent` + `sub` (agent delegate identifier)

### 4.3 Actor Claim Support
- **Location**: `core/src/main/java/org/keycloak/representations/AAuthActorClaim.java`
- **Pattern**: New claim class for `act` claim
- **Structure**: `agent`, `agent_delegate`, `sub`, nested `act` for multi-hop chains
- **Integration**: Add to `AAuthToken` or extend `AccessToken`

### 4.4 Federation Trust Management
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/federation/`
- **Files**:
  - `AuthServerTrustManager.java` - Manage trust relationships with upstream auth servers
  - **Storage**: Realm-level configuration for trusted auth server issuers
  - **Validation**: Verify upstream token issuer is trusted before exchange
- **Pattern**: Similar to identity provider trust configuration

**Testing**: Integration tests for token exchange, refresh flow, delegation chain validation

---

## Phase 5: Advanced Features & Polish

**Goal**: Complete specification features and production readiness

**Deliverables**:
1. Auth token encryption (JWE) support
2. Agent-aware authorization policies
3. Nonce replay prevention
4. Error handling and logging
5. Documentation and admin UI

**Key Components**:

### 5.1 Token Encryption Support
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/encryption/`
- **Files**:
  - `AAuthTokenEncryption.java` - Encrypt auth tokens using resource's public key
  - **Trigger**: When resource provides encryption key in Auth Request Document
  - **Format**: JWE wrapping signed JWT (JWS)
  - **Pattern**: Extend existing JWE support in Keycloak

### 5.2 Auth Request Document Support
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/authrequest/`
- **Files**:
  - `AuthRequestDocumentFetcher.java` - Fetch Auth Request Documents
  - `AuthRequestDocumentValidator.java` - Validate document signatures and expiration
  - **Usage**: When `auth_request_url` is provided instead of `scope`
- **Note**: Document format specification is TBD per spec, implement basic structure

### 5.3 Agent-Aware Authorization Policies
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/policy/`
- **Files**:
  - `AgentIdentityPolicyProvider.java` - Policy provider for agent-based access control
  - **Integration**: Extend existing authorization SPI
  - **Capabilities**: Agent allowlisting, agent-specific scopes, combined agent+user policies
- **Pattern**: Similar to existing policy providers in authorization services

### 5.4 Nonce Replay Prevention
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/replay/`
- **Files**:
  - `NonceCache.java` - Cache nonces with TTL for replay detection
  - **Integration**: Add nonce validation to `AAuthSignatureFilter`
  - **Scoping**: Cache keyed by (authority, public key, nonce) tuple
- **Pattern**: Similar to existing token reuse prevention

### 5.5 Error Handling
- **Location**: `services/src/main/java/org/keycloak/protocol/aauth/errors/`
- **Files**:
  - `AAuthErrorResponse.java` - Standardized error responses
  - **Format**: OAuth 2.0 error format with AAuth-specific error codes
  - **Integration**: Consistent error handling across all endpoints

### 5.6 Admin UI Integration
- **Location**: `js/apps/admin-ui/src/admin-ui/aauth/`
- **Files**:
  - Realm settings for AAuth configuration
  - Trusted auth servers management (for federation)
  - Agent allowlist/denylist configuration
- **Pattern**: Follow existing admin UI patterns

### 5.7 Documentation
- **Location**: `docs/documentation/server_admin/topics/protocols/aauth/`
- **Content**: Admin guide, protocol documentation, examples

**Testing**: Comprehensive test suite, performance testing, security audit

---

## Implementation Notes

### Coexistence Strategy
- All AAuth endpoints use `/protocol/aauth/` path (separate from `/protocol/openid-connect/`)
- No modifications to existing OAuth/OIDC endpoints
- Shared infrastructure (token storage, user sessions) where appropriate
- Feature flag/configuration to enable/disable AAuth per realm

### Key Dependencies
- HTTP Signature library (RFC 9421) - may need to add external dependency or implement
- Structured Fields parser (RFC 8941) - for `Signature-Key` header parsing
- JWK handling - Keycloak already has this via `org.keycloak.crypto`

### Testing Strategy
- Unit tests for each component
- Integration tests for each grant type flow
- End-to-end tests for complete scenarios
- Compatibility tests to ensure OAuth/OIDC unaffected

### Migration Path
- Phase 1-2: Foundation usable for basic direct grants
- Phase 3: Enables user consent flows
- Phase 4: Enables multi-hop and refresh
- Phase 5: Production-ready with all features

Each phase builds on previous phases and can be tested independently.

