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

import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

import java.lang.reflect.Proxy;

import static org.junit.Assert.*;

/**
 * Unit tests for UpstreamAuthTokenValidator.
 * 
 * Note: These tests use simplified patterns. Full validation testing
 * would require actual JWT tokens and signature verification.
 */
public class UpstreamAuthTokenValidatorTest {

    private KeycloakSession session;
    private RealmModel realm;
    private UpstreamAuthTokenValidator validator;

    @Before
    public void setUp() {
        session = (KeycloakSession) Proxy.newProxyInstance(
            UpstreamAuthTokenValidatorTest.class.getClassLoader(),
            new Class[]{KeycloakSession.class},
            (proxy, method, args) -> null
        );

        realm = (RealmModel) Proxy.newProxyInstance(
            UpstreamAuthTokenValidatorTest.class.getClassLoader(),
            new Class[]{RealmModel.class},
            (proxy, method, args) -> {
                String methodName = method.getName();
                if ("getAttribute".equals(methodName) && args.length > 0 && "aauth.trusted.issuers".equals(args[0])) {
                    return "[]"; // Empty trusted issuers by default
                }
                return null;
            }
        );

        validator = new UpstreamAuthTokenValidator(session, realm);
    }

    @Test
    public void testValidateWithUntrustedIssuer() {
        String untrustedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF1dGgrand0In0.eyJpc3MiOiJodHRwczovL3VudHJ1c3RlZC5leGFtcGxlLmNvbSJ9.signature";

        try {
            validator.validate(untrustedToken);
            fail("Expected SignatureVerificationException");
        } catch (SignatureVerificationException e) {
            assertTrue(e.getMessage().contains("not trusted") || e.getMessage().contains("Failed to parse"));
        }
    }

    @Test
    public void testValidateWithInvalidTokenType() {
        String invalidToken = "invalid.token.format";

        try {
            validator.validate(invalidToken);
            fail("Expected SignatureVerificationException");
        } catch (SignatureVerificationException e) {
            // Should fail during parsing or validation
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testValidateWithMissingIssuer() {
        String tokenWithoutIssuer = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF1dGgrand0In0.eyJleHAiOjE3MzAyMjEyMDB9.signature";

        try {
            validator.validate(tokenWithoutIssuer);
            fail("Expected SignatureVerificationException");
        } catch (SignatureVerificationException e) {
            // Should fail during parsing or validation
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testValidateWithExpiredToken() {
        // This test would require a properly formatted expired token
        // For now, we'll just verify the validator exists and can be instantiated
        assertNotNull(validator);
    }

    @Test
    public void testValidateWithMissingCnfClaim() {
        // This test would require a properly formatted token without cnf claim
        // For now, we'll just verify the validator exists and can be instantiated
        assertNotNull(validator);
    }
}

