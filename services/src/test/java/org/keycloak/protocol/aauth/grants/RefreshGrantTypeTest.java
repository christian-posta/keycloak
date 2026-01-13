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
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.representations.AAuthRefreshToken;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;

import java.lang.reflect.Proxy;
import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * Unit tests for RefreshGrantType.
 * 
 * Note: These tests use simplified mocking patterns consistent with Keycloak's test suite.
 * Full integration testing would require more complex setup.
 */
public class RefreshGrantTypeTest {

    private static ResteasyKeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private RealmModel realm;
    private KeyPair agentKeyPair;
    private KeyPair differentKeyPair;

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
        differentKeyPair = CryptoIntegration.getProvider().getKeyPairGen("Ed25519").generateKeyPair();
        
        // Create realm using Proxy
        realm = (RealmModel) Proxy.newProxyInstance(
            RefreshGrantTypeTest.class.getClassLoader(),
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
                if ("getSsoSessionMaxLifespan".equals(methodName)) {
                    return 2592000; // 30 days
                }
                if ("isEnabled".equals(methodName)) {
                    return true;
                }
                return null;
            }
        );
        
        // Create session
        session = new ResteasyKeycloakSession(sessionFactory);
        
        // Set session attributes for agent identity
        session.setAttribute("aauth.agent.id", "https://agent.example.com");
        session.setAttribute("aauth.agent.public.key", agentKeyPair.getPublic());
        session.setAttribute("aauth.signature.scheme", "jwks");
    }

    @Test
    public void testRefreshGrantTypeStructure() {
        RefreshGrantType grantType = new RefreshGrantType();
        assertNotNull("RefreshGrantType should be instantiable", grantType);
    }

    @Test
    public void testCreateRefreshToken() {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String resourceId = "https://resource.example.com";
        String scope = "profile email";
        
        String refreshToken = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, null, resourceId, scope, null, agentKeyPair.getPublic());
        
        assertNotNull("Refresh token should be created", refreshToken);
        assertTrue("Refresh token should be a JWT", refreshToken.contains("."));
    }

    @Test
    public void testValidateRefreshToken() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String resourceId = "https://resource.example.com";
        
        // Create refresh token
        String refreshTokenStr = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, null, resourceId, "profile", null, agentKeyPair.getPublic());
        
        // Validate refresh token
        AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenStr);
        
        assertNotNull("Refresh token should be valid", refreshToken);
        assertEquals("Agent ID should match", agentId, refreshToken.getAgent());
        assertEquals("Agent JKT should match", agentJkt, refreshToken.getAgentJkt());
        assertEquals("Resource ID should match", resourceId, refreshToken.getResourceId());
    }

    @Test
    public void testRefreshAuthToken() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String resourceId = "https://resource.example.com";
        
        // Create refresh token
        String refreshTokenStr = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, null, resourceId, "profile", null, agentKeyPair.getPublic());
        
        // Validate refresh token
        AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenStr);
        
        // Refresh auth token
        String newAuthToken = tokenManager.refreshAuthToken(realm, refreshToken, agentKeyPair.getPublic());
        
        assertNotNull("New auth token should be created", newAuthToken);
        assertTrue("New auth token should be a JWT", newAuthToken.contains("."));
    }

    @Test
    public void testAgentBindingMatch() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String resourceId = "https://resource.example.com";
        
        // Create refresh token with agent binding
        String refreshTokenStr = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, null, resourceId, "profile", null, agentKeyPair.getPublic());
        
        // Validate refresh token
        AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenStr);
        
        // Verify agent binding matches
        assertEquals("Agent ID should match", agentId, refreshToken.getAgent());
        assertEquals("Agent JKT should match", agentJkt, refreshToken.getAgentJkt());
    }

    @Test
    public void testAgentBindingMismatch() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String differentJkt = tokenManager.calculateAgentJkt(differentKeyPair.getPublic());
        String resourceId = "https://resource.example.com";
        
        // Create refresh token with original agent
        String refreshTokenStr = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, null, resourceId, "profile", null, agentKeyPair.getPublic());
        
        // Validate refresh token
        AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenStr);
        
        // Verify agent binding doesn't match different key
        assertNotEquals("Agent JKT should not match different key", differentJkt, refreshToken.getAgentJkt());
    }

    @Test
    public void testRefreshTokenWithAgentDelegate() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String agentDelegate = "https://delegate.example.com";
        String resourceId = "https://resource.example.com";
        
        // Create refresh token with agent delegate
        String refreshTokenStr = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, agentDelegate, resourceId, "profile", null, agentKeyPair.getPublic());
        
        // Validate refresh token
        AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenStr);
        
        assertEquals("Agent delegate should match", agentDelegate, refreshToken.getAgentDelegate());
    }

    @Test
    public void testRefreshTokenExpiration() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        String agentId = "https://agent.example.com";
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());
        String resourceId = "https://resource.example.com";
        
        // Create refresh token
        String refreshTokenStr = tokenManager.createRefreshToken(
                realm, agentId, agentJkt, null, resourceId, "profile", null, agentKeyPair.getPublic());
        
        // Validate refresh token
        AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenStr);
        
        assertNotNull("Refresh token expiration should be set", refreshToken.getExp());
        assertTrue("Refresh token should not be expired", refreshToken.getExp() > Time.currentTime());
    }

    @Test(expected = VerificationException.class)
    public void testInvalidRefreshToken() throws VerificationException {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        
        // Try to validate an invalid refresh token
        tokenManager.validateRefreshToken(realm, "invalid.token.here");
    }
}

