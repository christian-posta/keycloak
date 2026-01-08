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
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AAuthToken;
import org.keycloak.services.Urls;
import org.keycloak.util.JWKSUtils;

import java.security.PublicKey;

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
     * Get token expiration in seconds.
     */
    public long getTokenExpiration(RealmModel realm) {
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            return 300; // Default 5 minutes
        }
        return tokenLifespan;
    }
}

