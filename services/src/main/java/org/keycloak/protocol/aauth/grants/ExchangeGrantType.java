/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.aauth.grants;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.aauth.tokens.ResourceTokenValidator;
import org.keycloak.representations.AAuthActorClaim;
import org.keycloak.protocol.aauth.tokens.UpstreamAuthTokenValidator;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.representations.AAuthToken;
import org.keycloak.representations.AAuthTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Set;

/**
 * Exchange grant type for AAuth protocol (request_type=exchange).
 * 
 * Allows agents to exchange an upstream auth_token for a new auth_token
 * to access resources through delegation chains.
 * 
 * Flow:
 * 1. Extract resource_token from form parameters
 * 2. Extract upstream auth_token from Signature-Key header (scheme=jwt)
 * 3. Validate upstream auth_token (signature, issuer trust)
 * 4. Validate resource_token
 * 5. Authorize exchange (scope narrowing, delegation chain validation)
 * 6. Build actor claim from upstream token
 * 7. Generate new auth_token with act claim
 */
public class ExchangeGrantType implements OAuth2GrantType {

    private static final Logger logger = Logger.getLogger(ExchangeGrantType.class);

    @Override
    public EventType getEventType() {
        return EventType.TOKEN_EXCHANGE;
    }

    @Override
    public Set<String> getSupportedMultivaluedRequestParameters() {
        return Collections.emptySet();
    }

    @Override
    public Response process(Context context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        Cors cors = context.getCors();

        // Extract resource_token parameter
        String resourceToken = context.getFormParams().getFirst("resource_token");
        if (resourceToken == null || resourceToken.isEmpty()) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing required parameter: resource_token", Response.Status.BAD_REQUEST);
        }

        // Extract agent identity from session (set by AAuthSignatureFilter)
        String agentId = (String) session.getAttribute("aauth.agent.id");
        PublicKey agentPublicKey = (PublicKey) session.getAttribute("aauth.agent.public.key");
        String signatureScheme = (String) session.getAttribute("aauth.signature.scheme");

        if (agentPublicKey == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.", Response.Status.UNAUTHORIZED);
        }

        // Extract upstream auth token from session (set by JWTScheme when scheme=jwt)
        String upstreamAuthTokenString = (String) session.getAttribute("aauth.upstream.auth.token");
        if (upstreamAuthTokenString == null || upstreamAuthTokenString.isEmpty()) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing upstream auth_token. Request must be signed with scheme=jwt containing an auth+jwt token.",
                    Response.Status.BAD_REQUEST);
        }

        // For pseudonymous schemes (hwk) or when agentId is not available (jwt with pseudonymous token),
        // derive agent ID from public key
        if (agentId == null) {
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
            agentId = "pseudonymous:" + agentJkt;
            logger.debugf("Derived pseudonymous agent ID from public key: %s", agentId);
        }

        return processExchange(session, realm, cors, agentId, agentPublicKey, resourceToken, upstreamAuthTokenString);
    }

    private Response processExchange(KeycloakSession session, RealmModel realm, Cors cors,
            String agentId, PublicKey agentPublicKey, String resourceToken, String upstreamAuthTokenString) {

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
        String authServerId = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());

        try {
            // 1. Validate upstream auth token
            UpstreamAuthTokenValidator upstreamValidator = new UpstreamAuthTokenValidator(session, realm);
            UpstreamAuthTokenValidator.UpstreamTokenValidationResult upstreamResult = 
                    upstreamValidator.validate(upstreamAuthTokenString);

            // 2. Validate resource token
            ResourceTokenValidator resourceValidator = new ResourceTokenValidator(session, authServerId);
            ResourceTokenValidator.ResourceTokenValidationResult resourceResult = 
                    resourceValidator.validate(resourceToken, agentId, agentJkt);

            // 3. Authorize exchange (scope narrowing, delegation chain validation)
            authorizeExchange(upstreamResult, resourceResult);

            // 4. Build actor claim from upstream token
            AAuthActorClaim actorClaim = buildActorClaim(upstreamResult);

            // 5. Validate delegation chain (prevent circular delegation)
            validateDelegationChain(actorClaim, realm);

            // 6. Get user model if upstream token has subject
            UserModel user = null;
            if (upstreamResult.getSub() != null) {
                // Try to find user by subject ID
                // Note: In a real scenario, you might need to map upstream user IDs to local users
                user = session.users().getUserById(realm, upstreamResult.getSub());
            }

            // 7. Generate new auth token with actor claim
            String newAuthToken = tokenManager.createAuthTokenWithActor(
                    realm, agentId, null, // No agent_delegate for exchange
                    agentPublicKey, resourceResult.getResourceId(), resourceResult.getScope(),
                    user, actorClaim);

            // 8. Create response
            AAuthTokenResponse response = new AAuthTokenResponse();
            response.setAuthToken(newAuthToken);
            response.setExpiresIn(tokenManager.getTokenExpiration(realm));
            response.setTokenType("AAuth");

            logger.debugf("Token exchange successful for agent: %s, resource: %s, upstream agent: %s",
                    agentId, resourceResult.getResourceId(), upstreamResult.getAgentId());

            return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));

        } catch (SignatureVerificationException e) {
            logger.warnf(e, "Token exchange validation failed: %s", e.getMessage());
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Token exchange validation failed: " + e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (IllegalArgumentException e) {
            logger.warnf(e, "Token exchange authorization failed: %s", e.getMessage());
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Token exchange authorization failed: " + e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (Exception e) {
            logger.errorf(e, "Error during token exchange for agent: %s", agentId);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Error during token exchange: " + e.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Authorize the exchange by validating scope narrowing.
     * 
     * The new scope must be a subset of the upstream scope (scope narrowing).
     */
    private void authorizeExchange(UpstreamAuthTokenValidator.UpstreamTokenValidationResult upstreamResult,
            ResourceTokenValidator.ResourceTokenValidationResult resourceResult) {

        String upstreamScope = upstreamResult.getScope();
        String resourceScope = resourceResult.getScope();

        // If upstream has no scope, resource scope must also be empty or null
        if (upstreamScope == null || upstreamScope.trim().isEmpty()) {
            if (resourceScope != null && !resourceScope.trim().isEmpty()) {
                throw new IllegalArgumentException("Scope expansion not allowed: upstream token has no scope, but resource token requests scope: " + resourceScope);
            }
            return;
        }

        // If resource has no scope, that's fine (narrowing to no scope)
        if (resourceScope == null || resourceScope.trim().isEmpty()) {
            return;
        }

        // Check that resource scope is a subset of upstream scope
        Set<String> upstreamScopes = Set.of(upstreamScope.trim().split("\\s+"));
        Set<String> resourceScopes = Set.of(resourceScope.trim().split("\\s+"));

        if (!upstreamScopes.containsAll(resourceScopes)) {
            Set<String> invalidScopes = new java.util.HashSet<>(resourceScopes);
            invalidScopes.removeAll(upstreamScopes);
            throw new IllegalArgumentException("Scope expansion not allowed: resource token requests scopes not in upstream token: " + invalidScopes);
        }
    }

    /**
     * Build actor claim from upstream token validation result.
     */
    private AAuthActorClaim buildActorClaim(UpstreamAuthTokenValidator.UpstreamTokenValidationResult upstreamResult) {
        AAuthActorClaim actorClaim = new AAuthActorClaim();
        
        // Set upstream agent
        String upstreamAgentId = upstreamResult.getAgentId();
        if (upstreamAgentId == null) {
            // If no agent claim, use issuer as fallback (shouldn't happen in normal flow)
            upstreamAgentId = upstreamResult.getToken().getIssuer();
        }
        actorClaim.setAgent(upstreamAgentId);
        
        // Set upstream agent_delegate if present
        actorClaim.setAgentDelegate(upstreamResult.getAgentDelegate());
        
        // Set upstream user subject if present
        actorClaim.setSub(upstreamResult.getSub());
        
        // Extract nested act claim if present (multi-hop)
        AAuthToken upstreamToken = upstreamResult.getToken();
        if (upstreamToken.getAct() != null) {
            actorClaim.setAct(AAuthActorClaim.fromMap(upstreamToken.getAct()));
        }
        
        return actorClaim;
    }

    /**
     * Validate delegation chain to prevent circular delegation.
     * 
     * Checks that the delegation chain depth is within limits.
     * Note: Full circular delegation detection would require fetching upstream issuer metadata.
     */
    private void validateDelegationChain(AAuthActorClaim actorClaim, RealmModel realm) {
        // Check delegation chain depth
        AAuthActorClaim current = actorClaim;
        int depth = 0;
        int maxDepth = 10; // Prevent infinite loops

        while (current != null && depth < maxDepth) {
            // Check nested act claim
            if (current.getAct() != null) {
                current = current.getAct();
                depth++;
            } else {
                break;
            }
        }

        if (depth >= maxDepth) {
            throw new IllegalArgumentException("Delegation chain depth limit exceeded");
        }
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}

