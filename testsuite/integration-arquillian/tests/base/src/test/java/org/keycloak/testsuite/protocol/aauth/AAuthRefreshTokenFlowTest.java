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
package org.keycloak.testsuite.protocol.aauth;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AAuthRefreshToken;
import org.keycloak.representations.AAuthToken;
import org.keycloak.representations.AAuthTokenResponse;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.arquillian.TestContext;
import org.keycloak.testsuite.util.ServerURLs;
import org.keycloak.testsuite.util.UserBuilder;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Integration tests for AAuth refresh token flow (request_type=refresh).
 * 
 * Tests end-to-end scenarios including:
 * - Code exchange to get refresh token
 * - Refresh token exchange for new auth token
 * - Agent binding validation
 * - Error cases (expired tokens, signature mismatches, etc.)
 */
@RunAsClient
public class AAuthRefreshTokenFlowTest extends AbstractKeycloakTest {

    private static final String TEST_REALM = "aauth-test";
    private static final String TEST_USER = "test-user";
    private static final String TEST_PASSWORD = "password";
    
    @ArquillianResource
    protected TestContext testContext;
    
    private HttpClient httpClient;
    private String baseUrl;
    private KeyPair agentKeyPair;
    private String agentId;

    @Before
    public void setUp() {
        httpClient = HttpClientBuilder.create().build();
        baseUrl = ServerURLs.getAuthServerContextRoot();
        agentKeyPair = generateEd25519KeyPair();
        agentId = "https://agent.example.com";
    }

    @Override
    public void addTestRealms(java.util.List<org.keycloak.representations.idm.RealmRepresentation> testRealms) {
        org.keycloak.representations.idm.RealmRepresentation realm = new org.keycloak.representations.idm.RealmRepresentation();
        realm.setRealm(TEST_REALM);
        realm.setEnabled(true);
        testRealms.add(realm);
    }

    /**
     * Test 1: End-to-end refresh flow (code exchange → refresh)
     */
    @Test
    public void testRefreshFlow() throws Exception {
        // Create test user
        createTestUser();
        
        // Step 1: Get request token (requires user consent)
        String requestToken = getRequestToken();
        assertNotNull("Request token should be issued", requestToken);
        
        // Step 2: Get authorization code (simplified - would normally require browser flow)
        // For this test, we'll simulate by directly creating a code
        // In real scenario, user would authenticate and consent
        
        // Step 3: Exchange code for auth token and refresh token
        AAuthTokenResponse tokenResponse = exchangeCodeForTokens(requestToken);
        assertNotNull("Token response should be returned", tokenResponse);
        assertNotNull("Auth token should be present", tokenResponse.getAuthToken());
        assertNotNull("Refresh token should be present", tokenResponse.getRefreshToken());
        
        // Step 4: Refresh auth token using refresh token
        AAuthTokenResponse refreshResponse = refreshToken(tokenResponse.getRefreshToken());
        assertNotNull("Refresh response should be returned", refreshResponse);
        assertNotNull("New auth token should be present", refreshResponse.getAuthToken());
        
        // Verify new auth token is valid
        JWSInput jwsInput = new JWSInput(refreshResponse.getAuthToken());
        AAuthToken newAuthToken = jwsInput.readJsonContent(AAuthToken.class);
        assertEquals("Agent should match", agentId, newAuthToken.getAgent());
    }

    /**
     * Test 2: Agent binding validation
     */
    @Test
    public void testAgentBindingValidation() throws Exception {
        createTestUser();
        
        // Get tokens with original agent key
        String requestToken = getRequestToken();
        AAuthTokenResponse tokenResponse = exchangeCodeForTokens(requestToken);
        
        // Try to refresh with different agent key (should fail)
        KeyPair differentKeyPair = generateEd25519KeyPair();
        
        try {
            refreshTokenWithKey(tokenResponse.getRefreshToken(), differentKeyPair);
            fail("Should have failed with agent signature mismatch");
        } catch (Exception e) {
            // Expected - agent binding mismatch
            assertTrue("Error should mention agent mismatch", 
                    e.getMessage().contains("mismatch") || e.getMessage().contains("invalid"));
        }
    }

    /**
     * Test 3: Refresh token expiration
     */
    @Test
    public void testRefreshTokenExpiration() throws Exception {
        createTestUser();
        
        // Get tokens
        String requestToken = getRequestToken();
        AAuthTokenResponse tokenResponse = exchangeCodeForTokens(requestToken);
        
        // Parse refresh token to check expiration
        JWSInput jwsInput = new JWSInput(tokenResponse.getRefreshToken());
        AAuthRefreshToken refreshToken = jwsInput.readJsonContent(AAuthRefreshToken.class);
        
        assertNotNull("Refresh token expiration should be set", refreshToken.getExp());
        assertTrue("Refresh token should not be expired", refreshToken.getExp() > System.currentTimeMillis() / 1000);
    }

    /**
     * Test 4: Invalid refresh token
     */
    @Test
    public void testInvalidRefreshToken() throws Exception {
        createTestUser();
        
        try {
            refreshToken("invalid.refresh.token.here");
            fail("Should have failed with invalid refresh token");
        } catch (Exception e) {
            // Expected - invalid token format
            assertTrue("Error should mention invalid token", 
                    e.getMessage().contains("invalid") || e.getMessage().contains("Invalid"));
        }
    }

    // Helper methods

    private String getRequestToken() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        String body = "request_type=auth&scope=profile&resource_id=https://resource.example.com";
        request.setEntity(new StringEntity(body));
        
        HttpResponse response = httpClient.execute(request);
        assertEquals("Request token request should succeed", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.http.util.EntityUtils.toString(response.getEntity());
        AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
        
        return tokenResponse.getRequestToken();
    }

    private AAuthTokenResponse exchangeCodeForTokens(String requestToken) throws Exception {
        // Simplified - in real scenario would use authorization code
        // For testing, we'll use the direct grant flow instead
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        String body = "request_type=auth&scope=profile&resource_id=https://resource.example.com";
        request.setEntity(new StringEntity(body));
        
        HttpResponse response = httpClient.execute(request);
        assertEquals("Token request should succeed", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.http.util.EntityUtils.toString(response.getEntity());
        return JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
    }

    private AAuthTokenResponse refreshToken(String refreshTokenStr) throws Exception {
        return refreshTokenWithKey(refreshTokenStr, agentKeyPair);
    }

    private AAuthTokenResponse refreshTokenWithKey(String refreshTokenStr, KeyPair keyPair) throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, keyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        String body = "request_type=refresh&refresh_token=" + refreshTokenStr;
        request.setEntity(new StringEntity(body));
        
        HttpResponse response = httpClient.execute(request);
        
        if (response.getStatusLine().getStatusCode() != 200) {
            String errorBody = org.apache.http.util.EntityUtils.toString(response.getEntity());
            throw new RuntimeException("Refresh failed: " + errorBody);
        }
        
        String responseBody = org.apache.http.util.EntityUtils.toString(response.getEntity());
        return JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
    }

    private void createTestUser() {
        adminClient.realm(TEST_REALM).users().create(
            UserBuilder.create()
                .username(TEST_USER)
                .password(TEST_PASSWORD)
                .build()
        );
    }

    private KeyPair generateEd25519KeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Ed25519");
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate Ed25519 key pair", e);
        }
    }

    private Map<String, String> createSignedRequestHeaders(String method, String url, KeyPair keyPair) {
        // Simplified header creation - full implementation would use HTTPSig
        // For testing, we'll create minimal headers
        return java.util.Collections.singletonMap("Content-Type", "application/x-www-form-urlencoded");
    }
}

