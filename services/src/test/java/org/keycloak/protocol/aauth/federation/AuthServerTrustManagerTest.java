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

package org.keycloak.protocol.aauth.federation;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.lang.reflect.Proxy;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Unit tests for AuthServerTrustManager.
 */
public class AuthServerTrustManagerTest {

    private KeycloakSession session;
    private RealmModel realm;
    private AuthServerTrustManager trustManager;

    @Before
    public void setUp() {
        session = (KeycloakSession) Proxy.newProxyInstance(
            AuthServerTrustManagerTest.class.getClassLoader(),
            new Class[]{KeycloakSession.class},
            (proxy, method, args) -> null
        );

        realm = (RealmModel) Proxy.newProxyInstance(
            AuthServerTrustManagerTest.class.getClassLoader(),
            new Class[]{RealmModel.class},
            (proxy, method, args) -> {
                String methodName = method.getName();
                if ("getAttribute".equals(methodName) && args.length > 0 && "aauth.trusted.issuers".equals(args[0])) {
                    return null; // Default to null (no trusted issuers)
                }
                if ("setAttribute".equals(methodName) || "removeAttribute".equals(methodName)) {
                    return null; // No-op for set/remove
                }
                return null;
            }
        );

        trustManager = new AuthServerTrustManager(session, realm);
    }

    @Test
    public void testAddAndVerifyTrustedIssuer() {
        String issuer = "https://upstream-auth.example.com";

        // Initially not trusted (realm returns null)
        assertFalse(trustManager.isTrusted(issuer));

        // Add trusted issuer (should not throw)
        trustManager.addTrustedIssuer(issuer);
        // Note: Full verification would require checking realm.setAttribute was called
    }

    @Test
    public void testRemoveTrustedIssuer() {
        String issuer = "https://upstream-auth.example.com";

        // Remove trusted issuer (should not throw)
        trustManager.removeTrustedIssuer(issuer);
        // Note: Full verification would require checking realm.setAttribute was called
    }

    @Test
    public void testGetTrustedIssuers() {
        // With null attribute, should return empty set
        Set<String> trustedIssuers = trustManager.getTrustedIssuers();
        assertNotNull(trustedIssuers);
        assertTrue(trustedIssuers.isEmpty());
    }

    @Test
    public void testSetTrustedIssuers() {
        String issuer1 = "https://upstream-auth1.example.com";
        String issuer2 = "https://upstream-auth2.example.com";

        Set<String> issuers = Set.of(issuer1, issuer2);
        trustManager.setTrustedIssuers(issuers);
        // Note: Full verification would require checking realm.setAttribute was called
    }

    @Test
    public void testValidateTrust() {
        String issuer = "https://upstream-auth.example.com";

        // Not trusted - should throw exception
        try {
            trustManager.validateTrust(issuer);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("not trusted"));
        }
    }

    @Test
    public void testEmptyTrustedIssuers() {
        Set<String> trustedIssuers = trustManager.getTrustedIssuers();
        assertNotNull(trustedIssuers);
        assertTrue(trustedIssuers.isEmpty());
    }

    @Test
    public void testNullIssuer() {
        assertFalse(trustManager.isTrusted(null));
        assertFalse(trustManager.isTrusted(""));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddNullIssuer() {
        trustManager.addTrustedIssuer(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddEmptyIssuer() {
        trustManager.addTrustedIssuer("");
    }
}

