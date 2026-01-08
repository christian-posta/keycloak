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

package org.keycloak.protocol.aauth.signing.schemes;

import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.protocol.aauth.tokens.AgentTokenValidator;
import org.keycloak.protocol.aauth.tokens.AuthTokenValidator;
import org.keycloak.representations.JsonWebToken;

import java.security.PublicKey;
import java.util.Map;

/**
 * Signature scheme handler for scheme=jwt.
 * 
 * Validates either an agent token (agent+jwt) or auth token (auth+jwt),
 * then extracts the public key from the cnf.jwk claim.
 */
public class JWTScheme implements SignatureScheme {

    private final KeycloakSession session;

    public JWTScheme(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PublicKey discoverPublicKey(SignatureKeyParser keyParser) throws Exception {
        String jwtString = keyParser.getJWT();
        
        if (jwtString == null) {
            throw new SignatureVerificationException("Missing 'jwt' parameter in Signature-Key for scheme=jwt");
        }

        // Parse JWT
        JWSInput jws;
        try {
            jws = new JWSInput(jwtString);
        } catch (org.keycloak.jose.jws.JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse JWT in scheme=jwt", e);
        }
        
        // Determine token type from typ header
        String typ = jws.getHeader().getType();
        
        if ("agent+jwt".equals(typ)) {
            // Validate agent token and extract cnf.jwk
            AgentTokenValidator validator = new AgentTokenValidator(session);
            Map<String, Object> cnf = validator.validateAndExtractCnf(jwtString);
            return extractPublicKeyFromCnf(cnf);
            
        } else if ("auth+jwt".equals(typ)) {
            // Validate auth token and extract cnf.jwk
            AuthTokenValidator validator = new AuthTokenValidator(session);
            Map<String, Object> cnf = validator.validateAndExtractCnf(jwtString);
            return extractPublicKeyFromCnf(cnf);
            
        } else {
            throw new SignatureVerificationException("Unsupported JWT type in scheme=jwt: " + typ);
        }
    }

    /**
     * Extract public key from cnf.jwk claim.
     */
    private PublicKey extractPublicKeyFromCnf(Map<String, Object> cnf) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> jwkMap = (Map<String, Object>) cnf.get("jwk");
        
        if (jwkMap == null) {
            throw new SignatureVerificationException("Missing cnf.jwk claim in JWT");
        }

        // Convert map to JWK JSON and parse
        String jwkJson = org.keycloak.util.JsonSerialization.writeValueAsString(jwkMap);
        JWK jwk = org.keycloak.util.JsonSerialization.readValue(jwkJson, JWK.class);
        
        return JWKParser.create(jwk).toPublicKey();
    }

    @Override
    public String getAlgorithm(SignatureKeyParser keyParser) {
        try {
            String jwtString = keyParser.getJWT();
            if (jwtString == null) {
                return "Ed25519"; // Default
            }
            
            // Parse JWT header to get algorithm
            JWSInput jws = new JWSInput(jwtString);
            String alg = jws.getHeader().getRawAlgorithm();
            
            // Map JWT algorithm names to HTTPSig algorithm names
            if (alg != null) {
                // EdDSA uses Ed25519 in HTTPSig
                if ("EdDSA".equals(alg)) {
                    return "Ed25519";
                }
                // RSA algorithms map directly
                if (alg.startsWith("RS") || alg.startsWith("PS")) {
                    return alg;
                }
                // EC algorithms map directly
                if (alg.startsWith("ES")) {
                    return alg;
                }
            }
            
            return "Ed25519"; // Default fallback
        } catch (Exception e) {
            return "Ed25519"; // Default on error
        }
    }

    @Override
    public String getAgentId(SignatureKeyParser keyParser) {
        try {
            String jwtString = keyParser.getJWT();
            if (jwtString == null) {
                return null;
            }
            
            // Parse JWT to extract agent ID
            JWSInput jws = new JWSInput(jwtString);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            String typ = jws.getHeader().getType();
            
            if ("agent+jwt".equals(typ)) {
                // For agent tokens, agent ID is the issuer
                return token.getIssuer();
            } else if ("auth+jwt".equals(typ)) {
                // For auth tokens, agent ID is in the 'agent' claim
                Map<String, Object> otherClaims = token.getOtherClaims();
                if (otherClaims != null) {
                    Object agent = otherClaims.get("agent");
                    if (agent instanceof String) {
                        return (String) agent;
                    }
                }
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}

