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

package org.keycloak.protocol.aauth.tokens;

import org.jboss.logging.Logger;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;

/**
 * Validates auth tokens (auth+jwt) per AAuth specification Section 7.7.
 * 
 * This is a simplified validator for use in scheme=jwt signature verification.
 * Full validation will be implemented in Phase 2 when auth tokens are issued.
 */
public class AuthTokenValidator {

    private static final Logger logger = Logger.getLogger(AuthTokenValidator.class);

    public AuthTokenValidator(KeycloakSession session) {
        // Session may be used in future for full token validation
    }

    /**
     * Validate auth token and extract cnf claim.
     * 
     * @param authTokenString The auth token JWT string
     * @return The cnf claim as a Map
     * @throws SignatureVerificationException If validation fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> validateAndExtractCnf(String authTokenString) throws SignatureVerificationException {
        try {
            // 1. Parse JWT
            JWSInput jws = new JWSInput(authTokenString);
            
            // 2. Verify typ is "auth+jwt"
            String typ = jws.getHeader().getType();
            if (!"auth+jwt".equals(typ)) {
                throw new SignatureVerificationException("Invalid token type, expected 'auth+jwt', got: " + typ);
            }

            // 3. Extract claims
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            String iss = token.getIssuer();
            
            if (iss == null) {
                throw new SignatureVerificationException("Missing 'iss' claim in auth token");
            }

            // 4. Validate expiration
            if (token.getExp() == null) {
                throw new SignatureVerificationException("Missing 'exp' claim in auth token");
            }
            
            if (token.isExpired()) {
                throw new SignatureVerificationException("Auth token has expired");
            }

            // 5. Extract cnf claim
            Map<String, Object> otherClaims = token.getOtherClaims();
            if (otherClaims == null) {
                throw new SignatureVerificationException("Missing 'cnf' claim in auth token");
            }

            Object cnfObj = otherClaims.get("cnf");
            if (cnfObj == null) {
                throw new SignatureVerificationException("Missing 'cnf' claim in auth token");
            }

            if (!(cnfObj instanceof Map)) {
                throw new SignatureVerificationException("Invalid 'cnf' claim format in auth token");
            }

            Map<String, Object> cnf = (Map<String, Object>) cnfObj;
            
            // 6. Validate cnf.jwk exists
            Object jwkObj = cnf.get("jwk");
            if (jwkObj == null) {
                throw new SignatureVerificationException("Missing 'cnf.jwk' claim in auth token");
            }

            // Note: Full signature verification against auth server JWKS will be done
            // when this is used in token exchange scenarios (Phase 4)
            
            logger.debugf("Auth token validated successfully for issuer: %s", iss);
            
            return cnf;

        } catch (JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse auth token", e);
        } catch (Exception e) {
            if (e instanceof SignatureVerificationException) {
                throw e;
            }
            throw new SignatureVerificationException("Failed to validate auth token", e);
        }
    }
}

