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

package org.keycloak.protocol.aauth.storage;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.*;

/**
 * Unit tests for AAuthRequestTokenStore.
 */
public class AAuthRequestTokenStoreTest {

    private KeycloakSession session;
    private InMemorySingleUseObjectProvider store;

    @Before
    public void setUp() {
        store = new InMemorySingleUseObjectProvider();
        
        // Create a mock KeycloakSession using Proxy
        session = (KeycloakSession) Proxy.newProxyInstance(
            AAuthRequestTokenStoreTest.class.getClassLoader(),
            new Class[]{KeycloakSession.class},
            (proxy, method, args) -> {
                if ("singleUseObjects".equals(method.getName())) {
                    return store;
                }
                return null;
            }
        );
    }

    @Test
    public void testCreateRequestToken() {
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        
        String requestToken = tokenStore.createRequestToken(
                "https://agent.example.com",
                "agent-jkt-123",
                "jwks",
                "https://resource.example.com",
                "scope1 scope2",
                null,
                "https://agent.example.com/callback",
                "state-123"
        );
        
        assertNotNull("Request token should not be null", requestToken);
        assertTrue("Request token should contain dots", requestToken.contains("."));
        
        // Verify token was stored
        String[] parts = requestToken.split("\\.", 3);
        String tokenId = parts[0];
        assertNotNull("Token ID should be stored", store.get(tokenId));
    }

    @Test
    public void testValidateRequestToken() {
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        
        String requestToken = tokenStore.createRequestToken(
                "https://agent.example.com",
                "agent-jkt-123",
                "jwks",
                "https://resource.example.com",
                "scope1",
                null,
                "https://agent.example.com/callback",
                null
        );
        
        AAuthRequestToken validated = tokenStore.validateRequestToken(requestToken);
        
        assertNotNull("Validated token should not be null", validated);
        assertEquals("Agent ID should match", "https://agent.example.com", validated.getAgentId());
        assertEquals("Resource ID should match", "https://resource.example.com", validated.getResourceId());
        assertEquals("Scope should match", "scope1", validated.getScope());
    }

    @Test
    public void testValidateRequestTokenExpired() {
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        
        String requestToken = tokenStore.createRequestToken(
                "https://agent.example.com",
                "agent-jkt-123",
                "jwks",
                "https://resource.example.com",
                "scope1",
                null,
                "https://agent.example.com/callback",
                null
        );
        
        // Manually expire the token in the store
        String[] parts = requestToken.split("\\.", 3);
        String tokenId = parts[0];
        Map<String, String> tokenData = store.get(tokenId);
        if (tokenData != null) {
            tokenData.put("exp", String.valueOf(Time.currentTime() - 100)); // Expired
            store.put(tokenId, 0, tokenData); // Update with 0 lifespan
        }
        
        AAuthRequestToken validated = tokenStore.validateRequestToken(requestToken);
        
        assertNull("Expired token should return null", validated);
    }

    @Test
    public void testConsumeRequestToken() {
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        
        String requestToken = tokenStore.createRequestToken(
                "https://agent.example.com",
                "agent-jkt-123",
                "jwks",
                "https://resource.example.com",
                "scope1",
                null,
                "https://agent.example.com/callback",
                null
        );
        
        String[] parts = requestToken.split("\\.", 3);
        String tokenId = parts[0];
        
        boolean consumed = tokenStore.consumeRequestToken(requestToken);
        
        assertTrue("Token should be consumed", consumed);
        assertNull("Token should be removed after consumption", store.get(tokenId));
    }

    @Test
    public void testValidateRequestTokenNotFound() {
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        
        // Invalid token format
        AAuthRequestToken validated = tokenStore.validateRequestToken("invalid-token");
        assertNull("Invalid format should return null", validated);
        
        // Token not found
        validated = tokenStore.validateRequestToken("abc.123.hash");
        assertNull("Non-existent token should return null", validated);
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
