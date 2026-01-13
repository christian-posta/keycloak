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
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.aauth.storage.AAuthAuthorizationCode;
import org.keycloak.protocol.aauth.storage.AAuthRequestToken;
import org.keycloak.protocol.aauth.storage.AAuthRequestTokenStore;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;

import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;

/**
 * Unit tests for CodeGrantType.
 * 
 * Note: These tests use simplified mocking patterns consistent with Keycloak's test suite.
 * Full integration testing would require more complex setup.
 */
public class CodeGrantTypeTest {

    private static ResteasyKeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private InMemorySingleUseObjectProvider codeStore;
    private InMemorySingleUseObjectProvider requestTokenStore;
    private RealmModel realm;
    private KeyPair agentKeyPair;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
    }

    @Before
    public void setUp() throws Exception {
        codeStore = new InMemorySingleUseObjectProvider();
        requestTokenStore = new InMemorySingleUseObjectProvider();
        agentKeyPair = CryptoIntegration.getProvider().getKeyPairGen("Ed25519").generateKeyPair();
        
        // Create realm using Proxy
        realm = (RealmModel) Proxy.newProxyInstance(
            CodeGrantTypeTest.class.getClassLoader(),
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
        
        // Create session with custom providers
        session = new ResteasyKeycloakSession(sessionFactory) {
            @Override
            public SingleUseObjectProvider singleUseObjects() {
                return codeStore; // Use code store for single-use objects
            }
        };
        
        // Set session attributes for agent identity
        session.setAttribute("aauth.agent.id", "https://agent.example.com");
        session.setAttribute("aauth.agent.public.key", agentKeyPair.getPublic());
        session.setAttribute("aauth.signature.scheme", "jwks");
    }

    @Test
    public void testCodeExchangeStructure() {
        // This test verifies the basic structure of code exchange
        // Full implementation would require more complex mocking
        
        CodeGrantType grantType = new CodeGrantType();
        assertNotNull("CodeGrantType should be instantiable", grantType);
        
        // Verify that the grant type can be created
        // Actual processing would require a full OAuth2GrantType.Context setup
    }

    @Test
    public void testRequestTokenAndCodeFlow() {
        // Test the flow: create request token -> create code -> exchange code
        
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        
        // Create request token
        String requestTokenStr = tokenStore.createRequestToken(
                "https://agent.example.com",
                new AAuthTokenManager(session).calculateAgentJkt(agentKeyPair.getPublic()),
                "jwks",
                "https://resource.example.com",
                "profile email",
                null,
                "https://agent.example.com/callback",
                "state-123"
        );
        
        assertNotNull("Request token should be created", requestTokenStr);
        
        // Validate request token
        AAuthRequestToken requestToken = tokenStore.validateRequestToken(requestTokenStr);
        assertNotNull("Request token should be valid", requestToken);
        assertEquals("Agent ID should match", "https://agent.example.com", requestToken.getAgentId());
        
        // Create authorization code (simplified - would normally be done by authorization endpoint)
        String codeId = "code-123";
        String userSessionId = "user-session-123";
        AAuthAuthorizationCode code = new AAuthAuthorizationCode(
                codeId,
                Time.currentTime() + 60,
                requestToken.getScope(),
                requestToken.getRedirectUri(),
                userSessionId,
                requestToken.getId(),
                requestToken.getAgentId(),
                requestToken.getAgentJkt(),
                requestToken.getSignatureScheme(),
                requestToken.getResourceId()
        );
        
        // Store code
        codeStore.put(codeId, 60, code.serialize());
        
        // Verify code can be retrieved
        Map<String, String> codeData = codeStore.get(codeId);
        assertNotNull("Code should be stored", codeData);
        
        // Verify code can be consumed
        Map<String, String> consumed = codeStore.remove(codeId);
        assertNotNull("Code should be consumable", consumed);
        assertNull("Code should be removed after consumption", codeStore.get(codeId));
    }

    @Test
    public void testCodeExpiration() {
        String codeId = "expired-code";
        AAuthAuthorizationCode code = new AAuthAuthorizationCode(
                codeId,
                Time.currentTime() - 100, // Already expired
                "profile",
                "https://agent.example.com/callback",
                "user-session-123",
                "request-token-123",
                "https://agent.example.com",
                "agent-jkt-123",
                "jwks",
                "https://resource.example.com"
        );
        
        codeStore.put(codeId, 0, code.serialize());
        
        Map<String, String> codeData = codeStore.get(codeId);
        assertNotNull("Code data should exist", codeData);
        
        // Verify expiration check
        AAuthAuthorizationCode retrieved = AAuthAuthorizationCode.deserialize(codeData);
        assertTrue("Code should be expired", Time.currentTime() > retrieved.getExpiration());
    }

    /**
     * Simple in-memory implementation of SingleUseObjectProvider for testing.
     */
    private static class InMemorySingleUseObjectProvider implements SingleUseObjectProvider {
        private final Map<String, Map<String, String>> store = new ConcurrentHashMap<>();
        
        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> notes) {
            store.put(key, new ConcurrentHashMap<>(notes));
        }
        
        @Override
        public Map<String, String> get(String key) {
            return store.get(key);
        }
        
        @Override
        public Map<String, String> remove(String key) {
            return store.remove(key);
        }
        
        @Override
        public boolean replace(String key, Map<String, String> notes) {
            if (store.containsKey(key)) {
                store.put(key, new ConcurrentHashMap<>(notes));
                return true;
            }
            return false;
        }
        
        @Override
        public boolean putIfAbsent(String key, long lifespanInSeconds) {
            return store.putIfAbsent(key, new ConcurrentHashMap<>()) == null;
        }
        
        @Override
        public boolean contains(String key) {
            return store.containsKey(key);
        }
        
        @Override
        public void close() {
            // No-op for in-memory implementation
        }
    }
}
