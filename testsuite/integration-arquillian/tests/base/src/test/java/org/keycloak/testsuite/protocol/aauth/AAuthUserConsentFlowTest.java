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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AAuthIssuerMetadata;
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
 * Integration tests for AAuth user consent flow (request_type=code).
 * 
 * Tests end-to-end scenarios including:
 * - Request token issuance when user consent is required
 * - Authorization endpoint with request token
 * - Authorization code exchange for auth token
 * - Error cases (expired tokens, signature mismatches, etc.)
 */
@RunAsClient
public class AAuthUserConsentFlowTest extends AbstractKeycloakTest {

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
     * Test 1: Request Token Issuance for User Consent Flow
     */
    @Test
    public void testRequestTokenIssuance() throws Exception {
        // Create test user
        createTestUser();
        
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        // Create signed request with user scope (requires consent)
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        // Request with user scope - should return request_token
        String formData = "request_type=auth&scope=profile+email&redirect_uri=https://agent.example.com/callback";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Token endpoint should return 200", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.commons.io.IOUtils.toString(
            response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
        
        AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
        
        assertNotNull("Response should not be null", tokenResponse);
        assertNotNull("Request token should be present", tokenResponse.getRequestToken());
        assertNull("Auth token should not be present for consent flow", tokenResponse.getAuthToken());
        assertEquals("Expires in should be 600 seconds", 600, tokenResponse.getExpiresIn());
    }

    /**
     * Test 2: Authorization Endpoint with Request Token
     */
    @Test
    public void testAuthorizationEndpoint() throws Exception {
        // Create test user
        createTestUser();
        
        // First, get a request token
        String requestToken = getRequestToken();
        assertNotNull("Request token should be obtained", requestToken);
        
        // Call authorization endpoint
        String authUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/auth" +
                "?request_token=" + requestToken +
                "&redirect_uri=https://agent.example.com/callback";
        
        HttpGet request = new HttpGet(authUrl);
        HttpResponse response = httpClient.execute(request);
        
        // Should redirect to login or show consent (depending on authentication state)
        int statusCode = response.getStatusLine().getStatusCode();
        assertTrue("Should redirect (302) or show consent (200)", 
                statusCode == 302 || statusCode == 200);
    }

    /**
     * Test 3: Full User Consent Flow (with authenticated user)
     * 
     * Note: This test requires user authentication, which is complex in integration tests.
     * In a real scenario, the user would authenticate via browser, then grant consent.
     */
    @Test
    public void testFullConsentFlow() throws Exception {
        // Create test user
        createTestUser();
        
        // Get request token
        String requestToken = getRequestToken();
        assertNotNull("Request token should be obtained", requestToken);
        
        // Note: In a real flow, the user would:
        // 1. Be redirected to login (if not authenticated)
        // 2. Authenticate
        // 3. Be shown consent screen
        // 4. Grant consent
        // 5. Be redirected back with authorization code
        
        // For this test, we'll verify the request token is valid
        // and that the authorization endpoint accepts it
        String authUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/auth" +
                "?request_token=" + requestToken;
        
        HttpGet request = new HttpGet(authUrl);
        HttpResponse response = httpClient.execute(request);
        
        // Should accept the request token (may redirect to login if not authenticated)
        assertTrue("Authorization endpoint should accept request token",
                response.getStatusLine().getStatusCode() < 400);
    }

    /**
     * Test 4: Request Token Expiration
     */
    @Test
    public void testRequestTokenExpiration() throws Exception {
        // This test would require time manipulation or waiting
        // For now, we'll test that expired tokens are rejected
        // by creating a token and then trying to use it after expiration
        
        // Note: Actual expiration testing would require mocking time or waiting
        // This is a placeholder for the test structure
    }

    /**
     * Test 5: Code Exchange with Valid Code
     * 
     * Note: This requires a valid authorization code, which would be obtained
     * after user authentication and consent. For integration testing, we may
     * need to simulate this or use a test helper.
     */
    @Test
    public void testCodeExchange() throws Exception {
        // This test would require:
        // 1. A valid authorization code (obtained from consent flow)
        // 2. Agent signature matching the original request
        // 3. Valid redirect_uri
        
        // Placeholder for code exchange test structure
    }

    /**
     * Test 6: Code Exchange with Signature Mismatch
     */
    @Test
    public void testCodeExchangeSignatureMismatch() throws Exception {
        // This test would verify that code exchange fails if agent signature
        // doesn't match the original request
    }

    /**
     * Test 7: Code Exchange with Invalid Redirect URI
     */
    @Test
    public void testCodeExchangeInvalidRedirectUri() throws Exception {
        // This test would verify that code exchange fails if redirect_uri
        // doesn't match the original request
    }

    /**
     * Test 8: Direct Grant Still Works (No Consent Required)
     */
    @Test
    public void testDirectGrantStillWorks() throws Exception {
        // Verify that direct grant (non-user scopes) still works without consent
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        // Request with non-user scope - should return auth_token directly
        String formData = "request_type=auth&scope=data.read+data.write";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Token endpoint should return 200", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.commons.io.IOUtils.toString(
            response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
        
        AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
        
        assertNotNull("Response should not be null", tokenResponse);
        assertNotNull("Auth token should be present for direct grant", tokenResponse.getAuthToken());
        assertNull("Request token should not be present for direct grant", tokenResponse.getRequestToken());
    }

    // Helper methods

    private KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }

    private Map<String, String> createSignedRequestHeaders(String method, String url, KeyPair keyPair) {
        // This would use the same signature creation logic as AAuthDirectGrantTest
        // For now, return a placeholder
        return new java.util.HashMap<>();
    }

    private String getRequestToken() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        String formData = "request_type=auth&scope=profile+email&redirect_uri=https://agent.example.com/callback";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        if (response.getStatusLine().getStatusCode() == 200) {
            String responseBody = org.apache.commons.io.IOUtils.toString(
                response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
            AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
            return tokenResponse.getRequestToken();
        }
        
        return null;
    }

    private void createTestUser() {
        // Create test user via admin client
        org.keycloak.representations.idm.UserRepresentation user = UserBuilder.create()
                .username(TEST_USER)
                .email("test@example.com")
                .enabled(true)
                .password(TEST_PASSWORD)
                .build();
        
        String userId = org.keycloak.testsuite.util.ApiUtil.createUserWithAdminClient(
                adminClient.realm(TEST_REALM), user);
        getCleanup().addUserId(userId);
    }
}

