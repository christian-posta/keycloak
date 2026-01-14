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

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.util.Collections;

import static org.junit.Assert.*;

/**
 * Unit tests for ExchangeGrantType.
 */
public class ExchangeGrantTypeTest {

    private static ResteasyKeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private RealmModel realm;
    private KeyPair agentKeyPair;
    private Cors cors;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
    }

    @Before
    public void setUp() throws Exception {
        agentKeyPair = CryptoIntegration.getProvider().getKeyPairGen("Ed25519").generateKeyPair();

        realm = (RealmModel) Proxy.newProxyInstance(
            ExchangeGrantTypeTest.class.getClassLoader(),
            new Class[]{RealmModel.class},
            (proxy, method, args) -> {
                String methodName = method.getName();
                if ("getName".equals(methodName)) {
                    return "test-realm";
                }
                if ("getId".equals(methodName)) {
                    return "test-realm-id";
                }
                if ("getAccessTokenLifespan".equals(methodName)) {
                    return 300; // 5 minutes
                }
                if ("isEnabled".equals(methodName)) {
                    return true;
                }
                return null;
            }
        );

        session = new ResteasyKeycloakSession(sessionFactory);
        session.setAttribute("aauth.agent.id", "https://agent.example.com");
        session.setAttribute("aauth.agent.public.key", agentKeyPair.getPublic());
        session.setAttribute("aauth.signature.scheme", "jwks");
        session.setAttribute("aauth.upstream.auth.token", "mock-upstream-token");

        cors = Cors.builder().auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
    }

    private OAuth2GrantType.Context createContext(MultivaluedMap<String, String> formParams) {
        return new OAuth2GrantType.Context(session, null, null, formParams, null, cors, null);
    }

    @Test
    public void testMissingResourceTokenParameter() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>(); // No resource_token

        ExchangeGrantType grantType = new ExchangeGrantType();
        try {
            grantType.process(createContext(formParams));
            fail("Expected CorsErrorResponseException");
        } catch (CorsErrorResponseException e) {
            assertTrue(e.getErrorDescription().contains("Missing required parameter: resource_token"));
        }
    }

    @Test
    public void testMissingUpstreamAuthToken() {
        // Clear upstream token from session
        session.setAttribute("aauth.upstream.auth.token", null);

        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.add("resource_token", "mock-resource-token");

        ExchangeGrantType grantType = new ExchangeGrantType();
        try {
            grantType.process(createContext(formParams));
            fail("Expected CorsErrorResponseException");
        } catch (CorsErrorResponseException e) {
            assertTrue(e.getErrorDescription().contains("Missing upstream auth_token"));
        }
    }

    @Test
    public void testMissingAgentIdentity() {
        // Clear agent identity from session
        session.setAttribute("aauth.agent.id", null);
        session.setAttribute("aauth.agent.public.key", null);

        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.add("resource_token", "mock-resource-token");

        ExchangeGrantType grantType = new ExchangeGrantType();
        try {
            grantType.process(createContext(formParams));
            fail("Expected CorsErrorResponseException");
        } catch (CorsErrorResponseException e) {
            assertTrue(e.getErrorDescription().contains("Agent identity not found"));
        }
    }

    @Test
    public void testPseudonymousAgentId() {
        // Set pseudonymous scheme
        session.setAttribute("aauth.agent.id", null);
        session.setAttribute("aauth.signature.scheme", "hwk");

        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.add("resource_token", "mock-resource-token");

        ExchangeGrantType grantType = new ExchangeGrantType();
        // Should derive agent ID from public key
        // Note: This will fail later in validation, but we're testing the agent ID derivation
        try {
            grantType.process(createContext(formParams));
            // Expected to fail at validation, not at agent ID extraction
        } catch (CorsErrorResponseException e) {
            // Should not fail with "Agent identity not found" for pseudonymous schemes
            assertFalse(e.getErrorDescription().contains("Agent identity not found"));
        }
    }
}

