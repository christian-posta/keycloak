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

package org.keycloak.protocol.aauth;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AAuthActorClaim;
import org.keycloak.representations.AAuthRefreshToken;
import org.keycloak.representations.AAuthToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.util.JWKSUtils;

import java.security.PublicKey;
import java.util.Map;

/**
 * Token manager for creating AAuth tokens.
 * 
 * Creates auth tokens with typ="auth+jwt" header and AAuth-specific claims.
 */
public class AAuthTokenManager {

    private static final Logger logger = Logger.getLogger(AAuthTokenManager.class);

    private final KeycloakSession session;

    public AAuthTokenManager(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Create an auth token for the given agent and resource.
     * 
     * @param realm The realm
     * @param agentId Agent HTTPS URL
     * @param agentDelegate Agent delegate identifier (optional)
     * @param agentPublicKey Agent's public signing key (for cnf.jwk)
     * @param resourceId Resource identifier (aud claim)
     * @param scope Space-separated scopes (optional)
     * @param user User model (optional, for user authorization)
     * @return Signed auth token JWT string
     */
    public String createAuthToken(RealmModel realm, String agentId, String agentDelegate,
            PublicKey agentPublicKey, String resourceId, String scope, UserModel user) {
        
        // Create AAuthToken instance
        AAuthToken token = new AAuthToken();
        
        // Set issuer
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        token.issuer(issuer);
        
        // Set audience (resource identifier)
        token.audience(resourceId);
        
        // Set agent claim (if different from aud)
        if (!resourceId.equals(agentId)) {
            token.agent(agentId);
        }
        
        // Set agent_delegate if present
        if (agentDelegate != null) {
            token.agentDelegate(agentDelegate);
        }
        
        // Set scope if provided
        if (scope != null && !scope.trim().isEmpty()) {
            token.setScope(scope);
        }
        
        // Set user claims if user provided
        if (user != null) {
            token.subject(user.getId());
            // Additional user claims can be added here if needed
        }
        
        // Set expiration (use realm's access token lifespan)
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            tokenLifespan = 300; // Default 5 minutes if not configured
        }
        long expiration = Time.currentTime() + tokenLifespan;
        token.exp(expiration);
        
        // Set issued at
        token.issuedNow();
        
        // Convert agent's public key to JWK for cnf.jwk
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        token.setCnfJwk(agentJwk);
        
        // Get realm signing key and algorithm
        String signingAlgorithm = session.tokens().signatureAlgorithm(org.keycloak.TokenCategory.ACCESS);
        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, signingAlgorithm);
        
        if (signingKey == null) {
            throw new RuntimeException("Active signing key not found for algorithm: " + signingAlgorithm);
        }
        
        // Create signer context
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        
        // Build and sign JWT with typ="auth+jwt"
        String signedToken = new JWSBuilder()
                .type("auth+jwt")
                .kid(signingKey.getKid())
                .jsonContent(token)
                .sign(signer);
        
        logger.debugf("Created auth token for agent: %s, resource: %s", agentId, resourceId);
        
        return signedToken;
    }

    /**
     * Convert PublicKey to JWK for cnf.jwk claim.
     */
    private JWK convertPublicKeyToJWK(PublicKey publicKey) {
        String algorithm = publicKey.getAlgorithm();
        
        if ("EdDSA".equals(algorithm) || publicKey instanceof java.security.interfaces.EdECPublicKey) {
            // Ed25519 or Ed448
            return JWKBuilder.create().okp(publicKey);
        } else if ("RSA".equals(algorithm) || publicKey instanceof java.security.interfaces.RSAPublicKey) {
            return JWKBuilder.create().rsa(publicKey, null, null);
        } else if ("EC".equals(algorithm) || publicKey instanceof java.security.interfaces.ECPublicKey) {
            return JWKBuilder.create().ec(publicKey, null, null);
        } else {
            throw new RuntimeException("Unsupported public key type: " + algorithm);
        }
    }

    /**
     * Calculate JWK thumbprint (agent_jkt) from PublicKey.
     */
    public String calculateAgentJkt(PublicKey agentPublicKey) {
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        return JWKSUtils.computeThumbprint(agentJwk);
    }

    /**
     * Refresh by re-presenting an expired auth token (per updated AAuth spec Section 11.6).
     * Verifies the JWT signature (ignoring exp), verifies agent key binding via cnf.jwk,
     * then issues a new auth token with the same claims.
     *
     * @param realm The realm
     * @param expiredAuthTokenJwt The expired auth token JWT string
     * @param agentPublicKey The current agent's public key (must match cnf.jwk in the expired token)
     * @return New signed auth token JWT
     */
    @SuppressWarnings("unchecked")
    public String refreshFromExpiredAuthToken(RealmModel realm, String expiredAuthTokenJwt,
            PublicKey agentPublicKey) throws Exception {

        JWSInput jws = new JWSInput(expiredAuthTokenJwt);

        // Verify type
        String typ = jws.getHeader().getType();
        if (!"auth+jwt".equals(typ)) {
            throw new Exception("Invalid token type for refresh, expected auth+jwt, got: " + typ);
        }

        // Verify JWT signature (same logic as auth token validation)
        String kid = jws.getHeader().getKeyId();
        String algorithm = jws.getHeader().getRawAlgorithm();
        String normalizedAlg = "EdDSA".equals(algorithm) ? "Ed25519" : algorithm;

        KeyWrapper signingKey = session.keys().getKeysStream(realm)
                .filter(k -> k.getStatus().isEnabled())
                .filter(k -> KeyUse.SIG.equals(k.getUse()))
                .filter(k -> normalizedAlg.equals(k.getAlgorithm()))
                .filter(k -> kid == null || kid.equals(k.getKid()))
                .findFirst().orElse(null);

        if (signingKey == null) {
            throw new Exception("No key found to verify expired auth token: kid=" + kid + " alg=" + algorithm);
        }

        SignatureProvider sigProv = session.getProvider(SignatureProvider.class, normalizedAlg);
        if (sigProv == null) {
            throw new Exception("Unsupported signature algorithm: " + algorithm);
        }

        SignatureVerifierContext verifier = sigProv.verifier(signingKey);
        if (!verifier.verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature())) {
            throw new Exception("Expired auth token signature verification failed");
        }

        // Parse claims (ignoring exp)
        JsonWebToken token = jws.readJsonContent(JsonWebToken.class);

        // Verify cnf.jwk matches the current agent's public key
        String currentJkt = calculateAgentJkt(agentPublicKey);
        Map<String, Object> otherClaims = token.getOtherClaims();
        if (otherClaims != null && otherClaims.get("cnf") instanceof Map) {
            Map<String, Object> cnf = (Map<String, Object>) otherClaims.get("cnf");
            Object jwkObj = cnf.get("jwk");
            if (jwkObj instanceof Map) {
                try {
                    String jwkJson = org.keycloak.util.JsonSerialization.writeValueAsString(jwkObj);
                    JWK jwk = org.keycloak.util.JsonSerialization.readValue(jwkJson, JWK.class);
                    String tokenJkt = JWKSUtils.computeThumbprint(jwk);
                    if (!currentJkt.equals(tokenJkt)) {
                        throw new Exception("Agent key mismatch: cnf.jwk in token does not match current agent key");
                    }
                } catch (Exception e) {
                    if (e.getMessage() != null && e.getMessage().startsWith("Agent key mismatch")) throw e;
                    logger.warnf(e, "Could not verify cnf.jwk during token refresh");
                }
            }
        }

        // Extract claims
        String agentId = null;
        String agentDelegate = null;
        String resourceId = token.getAudience() != null && token.getAudience().length > 0
                ? token.getAudience()[0] : null;
        String scope = null;
        String subject = token.getSubject();

        if (otherClaims != null) {
            agentId = otherClaims.get("agent") instanceof String ? (String) otherClaims.get("agent") : null;
            agentDelegate = otherClaims.get("agent_delegate") instanceof String
                    ? (String) otherClaims.get("agent_delegate") : null;
            scope = otherClaims.get("scope") instanceof String ? (String) otherClaims.get("scope") : null;
        }

        if (agentId == null) agentId = resourceId; // self-access case

        // Issue new token with same claims
        UserModel user = null;
        if (subject != null) {
            user = session.users().getUserById(realm, subject);
        }

        return createAuthToken(realm, agentId, agentDelegate, agentPublicKey, resourceId, scope, user);
    }

    /**
     * Get token expiration in seconds.
     */
    public long getTokenExpiration(RealmModel realm) {
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            return 300; // Default 5 minutes
        }
        return tokenLifespan;
    }

    // ---- Deprecated refresh token methods kept for source compatibility ----
    // These are no longer called; token refresh is done via refreshFromExpiredAuthToken().

    @Deprecated
    public String createRefreshToken(RealmModel realm, String agentId, String agentJkt,
            String agentDelegate, String resourceId, String scope, UserModel user,
            PublicKey agentPublicKey) {
        
        // Create AAuthRefreshToken instance
        AAuthRefreshToken refreshToken = new AAuthRefreshToken();
        
        // Set issuer
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        refreshToken.issuer(issuer);
        
        // Set audience (resource identifier)
        refreshToken.audience(new String[] { issuer }); // Refresh tokens have issuer as audience
        
        // Set agent binding fields
        refreshToken.agent(agentId);
        refreshToken.agentJkt(agentJkt);
        
        if (agentDelegate != null) {
            refreshToken.agentDelegate(agentDelegate);
        }
        
        refreshToken.resourceId(resourceId);
        
        // Set scope if provided
        if (scope != null && !scope.trim().isEmpty()) {
            refreshToken.setScope(scope);
        }
        
        // Set user claims if user provided
        if (user != null) {
            refreshToken.subject(user.getId());
        }
        
        // Set expiration (use realm's refresh token lifespan, or default to 30 days)
        int refreshTokenLifespan = realm.getSsoSessionMaxLifespan();
        if (refreshTokenLifespan == -1) {
            refreshTokenLifespan = 2592000; // Default 30 days
        }
        long expiration = Time.currentTime() + refreshTokenLifespan;
        refreshToken.exp(expiration);
        
        // Set issued at
        refreshToken.issuedNow();
        
        // Generate token ID
        refreshToken.id(org.keycloak.models.utils.KeycloakModelUtils.generateId());
        
        // Convert agent's public key to JWK for cnf.jwk
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        refreshToken.setCnfJwk(agentJwk);
        
        // Get realm signing key and algorithm
        // Use ACCESS category (same as access tokens) instead of INTERNAL to avoid HMAC
        String signingAlgorithm = session.tokens().signatureAlgorithm(org.keycloak.TokenCategory.ACCESS);
        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, signingAlgorithm);
        
        if (signingKey == null) {
            throw new RuntimeException("Active signing key not found for algorithm: " + signingAlgorithm);
        }
        
        // Create signer context
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        
        // Build and sign JWT with typ="refresh+jwt"
        String signedToken = new JWSBuilder()
                .type("refresh+jwt")
                .kid(signingKey.getKid())
                .jsonContent(refreshToken)
                .sign(signer);
        
        logger.debugf("Created refresh token for agent: %s, resource: %s", agentId, resourceId);
        
        return signedToken;
    }

    @Deprecated
    public AAuthRefreshToken validateRefreshToken(RealmModel realm, String encodedRefreshToken)
            throws org.keycloak.common.VerificationException {
        
        throw new org.keycloak.common.VerificationException("Refresh tokens are no longer supported. Use refreshFromExpiredAuthToken() instead.");
    }

    @Deprecated
    public String refreshAuthToken(RealmModel realm, AAuthRefreshToken refreshToken,
            PublicKey agentPublicKey) {
        throw new UnsupportedOperationException("Refresh tokens are no longer supported. Use refreshFromExpiredAuthToken() instead.");
    }

    /**
     * Create an auth token with an actor claim for token exchange scenarios.
     * 
     * @param realm The realm
     * @param agentId Agent HTTPS URL (current agent making the exchange request)
     * @param agentDelegate Agent delegate identifier (optional)
     * @param agentPublicKey Agent's public signing key (for cnf.jwk)
     * @param resourceId Resource identifier (aud claim)
     * @param scope Space-separated scopes (optional, must be narrowed from upstream scope)
     * @param user User model (optional, for user authorization)
     * @param actorClaim Actor claim representing the upstream agent delegation chain
     * @return Signed auth token JWT string with act claim
     */
    public String createAuthTokenWithActor(RealmModel realm, String agentId, String agentDelegate,
            PublicKey agentPublicKey, String resourceId, String scope, UserModel user,
            AAuthActorClaim actorClaim) {
        
        // Create AAuthToken instance
        AAuthToken token = new AAuthToken();
        
        // Set issuer
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        token.issuer(issuer);
        
        // Set audience (resource identifier)
        token.audience(resourceId);
        
        // Set agent claim (current agent making the exchange request)
        token.agent(agentId);
        
        // Set agent_delegate if present
        if (agentDelegate != null) {
            token.agentDelegate(agentDelegate);
        }
        
        // Set scope if provided
        if (scope != null && !scope.trim().isEmpty()) {
            token.setScope(scope);
        }
        
        // Set user claims if user provided
        // If upstream token had a user, preserve it through the delegation chain
        if (user != null) {
            token.subject(user.getId());
        } else if (actorClaim != null && actorClaim.getSub() != null) {
            // Preserve upstream user subject if present
            token.subject(actorClaim.getSub());
        }
        
        // Set expiration (use realm's access token lifespan)
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            tokenLifespan = 300; // Default 5 minutes if not configured
        }
        long expiration = Time.currentTime() + tokenLifespan;
        token.exp(expiration);
        
        // Set issued at
        token.issuedNow();
        
        // Convert agent's public key to JWK for cnf.jwk
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        token.setCnfJwk(agentJwk);
        
        // Set actor claim (convert to Map for JWT)
        if (actorClaim != null) {
            Map<String, Object> actMap = actorClaim.toMap();
            token.setAct(actMap);
        }
        
        // Get realm signing key and algorithm
        String signingAlgorithm = session.tokens().signatureAlgorithm(org.keycloak.TokenCategory.ACCESS);
        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, signingAlgorithm);
        
        if (signingKey == null) {
            throw new RuntimeException("Active signing key not found for algorithm: " + signingAlgorithm);
        }
        
        // Create signer context
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        
        // Build and sign JWT with typ="auth+jwt"
        String signedToken = new JWSBuilder()
                .type("auth+jwt")
                .kid(signingKey.getKid())
                .jsonContent(token)
                .sign(signer);
        
        logger.debugf("Created auth token with actor claim for agent: %s, resource: %s, upstream agent: %s", 
                agentId, resourceId, actorClaim != null ? actorClaim.getAgent() : "N/A");
        
        return signedToken;
    }
}

