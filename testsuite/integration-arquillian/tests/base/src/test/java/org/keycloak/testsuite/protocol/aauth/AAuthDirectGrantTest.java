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
import org.jboss.resteasy.mock.MockHttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.protocol.aauth.signing.SignatureBaseBuilder;
import org.keycloak.representations.AAuthIssuerMetadata;
import org.keycloak.representations.AAuthToken;
import org.keycloak.representations.AAuthTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.resteasy.HttpRequestImpl;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.arquillian.TestContext;
import org.keycloak.testsuite.util.ServerURLs;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Integration tests for AAuth direct grant flow (request_type=auth).
 * 
 * Tests end-to-end scenarios including:
 * - Well-known metadata discovery
 * - Direct grant with resource token
 * - Direct grant with scope (agent as resource)
 * - Error cases
 * - Token validation
 */
@RunAsClient
public class AAuthDirectGrantTest extends AbstractKeycloakTest {

    private static final String TEST_REALM = "aauth-test";
    
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
     * Test 1: Well-Known Metadata Discovery
     */
    @Test
    public void testWellKnownMetadata() throws Exception {
        String metadataUrl = baseUrl + "/realms/" + TEST_REALM + "/.well-known/aauth-issuer";
        
        HttpGet request = new HttpGet(metadataUrl);
        request.setHeader("Accept", "application/json");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Metadata endpoint should return 200", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.commons.io.IOUtils.toString(
            response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
        
        AAuthIssuerMetadata metadata = JsonSerialization.readValue(responseBody, AAuthIssuerMetadata.class);
        
        assertNotNull("Metadata should not be null", metadata);
        assertNotNull("Issuer should be set", metadata.getIssuer());
        assertTrue("Issuer should contain realm name", metadata.getIssuer().contains("/realms/" + TEST_REALM));
        assertNotNull("JWKS URI should be set", metadata.getJwksUri());
        assertNotNull("Agent token endpoint should be set", metadata.getAgentTokenEndpoint());
        assertNotNull("Request types supported should be set", metadata.getRequestTypesSupported());
        assertTrue("Request types should include 'auth'", metadata.getRequestTypesSupported().contains("auth"));
        assertNotNull("Agent signing algorithms supported should be set", metadata.getAgentSigningAlgsSupported());
    }

    /**
     * Test 2: Direct Grant with Scope (Agent as Resource)
     */
    @Test
    public void testDirectGrantWithScope() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        // Create signed request
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        // Set form parameters
        String formData = "request_type=auth&scope=data.read+data.write";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Token request should return 200", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.commons.io.IOUtils.toString(
            response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
        
        AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
        
        assertNotNull("Token response should not be null", tokenResponse);
        assertNotNull("Auth token should be present", tokenResponse.getAuthToken());
        assertNotNull("Expires in should be set", tokenResponse.getExpiresIn());
        assertEquals("Token type should be AAuth", "AAuth", tokenResponse.getTokenType());
        
        // Validate auth token structure
        validateAuthToken(tokenResponse.getAuthToken(), agentId, agentId, "data.read data.write");
    }

    /**
     * Test 3: Direct Grant with Resource Token
     */
    @Test
    public void testDirectGrantWithResourceToken() throws Exception {
        String resourceId = "https://resource.example.com";
        String resourceToken = createMockResourceToken(resourceId, agentId, agentKeyPair.getPublic());
        
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        // Create signed request
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        // Set form parameters
        String formData = "request_type=auth&resource_token=" + java.net.URLEncoder.encode(resourceToken, "UTF-8");
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Token request should return 200", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.commons.io.IOUtils.toString(
            response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
        
        AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
        
        assertNotNull("Token response should not be null", tokenResponse);
        assertNotNull("Auth token should be present", tokenResponse.getAuthToken());
        
        // Validate auth token structure
        validateAuthToken(tokenResponse.getAuthToken(), agentId, resourceId, null);
    }

    /**
     * Test 4: Error Case - Missing Signature-Key Header
     */
    @Test
    public void testErrorMissingSignatureKey() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        HttpPost request = new HttpPost(tokenUrl);
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        String formData = "request_type=auth&scope=data.read";
        request.setEntity(new StringEntity(formData));
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Should return 401 Unauthorized", 401, response.getStatusLine().getStatusCode());
    }

    /**
     * Test 5: Error Case - Invalid Signature
     */
    @Test
    public void testErrorInvalidSignature() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        // Corrupt the signature
        headers.put("Signature", "sig=:invalid_signature:");
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        String formData = "request_type=auth&scope=data.read";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Should return 401 Unauthorized", 401, response.getStatusLine().getStatusCode());
    }

    /**
     * Test 6: Error Case - Missing Parameters
     */
    @Test
    public void testErrorMissingParameters() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        // Missing both resource_token and scope
        String formData = "request_type=auth";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Should return 400 Bad Request", 400, response.getStatusLine().getStatusCode());
    }

    /**
     * Test 7: Default request_type to "auth"
     */
    @Test
    public void testDefaultRequestType() throws Exception {
        String tokenUrl = baseUrl + "/realms/" + TEST_REALM + "/protocol/aauth/agent/token";
        
        Map<String, String> headers = createSignedRequestHeaders("POST", tokenUrl, agentKeyPair);
        
        HttpPost request = new HttpPost(tokenUrl);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }
        
        // Omit request_type parameter
        String formData = "scope=data.read";
        request.setEntity(new StringEntity(formData));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        HttpResponse response = httpClient.execute(request);
        
        assertEquals("Should return 200 with default request_type", 200, response.getStatusLine().getStatusCode());
        
        String responseBody = org.apache.commons.io.IOUtils.toString(
            response.getEntity().getContent(), java.nio.charset.StandardCharsets.UTF_8);
        
        AAuthTokenResponse tokenResponse = JsonSerialization.readValue(responseBody, AAuthTokenResponse.class);
        assertNotNull("Token response should not be null", tokenResponse);
        assertNotNull("Auth token should be present", tokenResponse.getAuthToken());
    }

    // ========== Helper Methods ==========

    /**
     * Generate Ed25519 key pair for testing
     */
    private KeyPair generateEd25519KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate Ed25519 key pair", e);
        }
    }

    /**
     * Create signed HTTP request headers using hwk scheme
     */
    private Map<String, String> createSignedRequestHeaders(String method, String url, KeyPair keyPair) throws Exception {
        Map<String, String> headers = new HashMap<>();
        
        URI uri = new URI(url);
        String scheme = uri.getScheme() != null ? uri.getScheme() : "http";
        String host = uri.getHost() + (uri.getPort() != -1 ? ":" + uri.getPort() : "");
        String path = uri.getPath();
        String query = uri.getQuery();
        
        // Create base URI and request URI for MockHttpRequest
        String baseUrl = scheme + "://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + path + (query != null ? "?" + query : ""));
        
        // Create MockHttpRequest to use SignatureBaseBuilder
        MockHttpRequest mockRequest = MockHttpRequest.create(method, baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Create Signature-Key header with hwk scheme
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = KeyUtils.createKeyId(keyPair.getPublic());
        String xValue;
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            xValue = ((org.keycloak.jose.jwk.OKPPublicJWK) jwk).getX();
        } else {
            xValue = (String) jwk.getOtherClaims().get("x");
        }
        String signatureKey = String.format("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"%s\";kid=\"%s\"", xValue, kid);
        mockRequest.header("Signature-Key", signatureKey);
        
        // Create Signature-Input header
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        
        // Build signature base using SignatureBaseBuilder
        HttpRequest httpRequest = new HttpRequestImpl(mockRequest);
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(httpRequest, signatureInput, "sig");
        
        // Sign the signature base
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setCurve(Algorithm.Ed25519);
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(keyWrapper);
        
        byte[] signatureBytes = signer.sign(signatureBase);
        String base64Signature = Base64Url.encode(signatureBytes);
        
        // Create Signature header
        String signature = "sig=:" + base64Signature + ":";
        
        // Extract headers for Apache HttpClient
        headers.put("Host", host);
        headers.put("Signature-Key", signatureKey);
        headers.put("Signature-Input", signatureInput);
        headers.put("Signature", signature);
        
        return headers;
    }

    /**
     * Create a mock resource token for testing
     */
    private String createMockResourceToken(String resourceId, String agentId, PublicKey agentPublicKey) throws Exception {
        // Create a simple resource token (signed by resource)
        // In a real scenario, this would be signed by the resource server
        JsonWebToken token = new JsonWebToken();
        token.type("resource+jwt");
        token.issuer(resourceId);
        token.audience(agentId);
        token.exp(Time.currentTime() + 3600); // 1 hour
        token.issuedNow();
        
        // Set agent claim
        token.getOtherClaims().put("agent", agentId);
        
        // Set agent_jkt (JWK thumbprint)
        JWK agentJwk = JWKBuilder.create().okp(agentPublicKey);
        String agentJkt = org.keycloak.util.JWKSUtils.computeThumbprint(agentJwk);
        token.getOtherClaims().put("agent_jkt", agentJkt);
        
        // Sign with a test key (in real scenario, this would be signed by resource)
        // For testing, we'll use the agent's key (not ideal, but works for integration test)
        KeyWrapper signingKey = new KeyWrapper();
        signingKey.setAlgorithm(Algorithm.EdDSA);
        signingKey.setKid("test-resource-key");
        signingKey.setPrivateKey(agentKeyPair.getPrivate()); // Using agent key for testing
        signingKey.setPublicKey(agentKeyPair.getPublic());
        signingKey.setCurve(Algorithm.Ed25519);
        
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(signingKey);
        
        return new JWSBuilder()
            .type("resource+jwt")
            .kid(signingKey.getKid())
            .jsonContent(token)
            .sign(signer);
    }

    /**
     * Validate auth token structure and claims
     */
    private void validateAuthToken(String authToken, String expectedAgent, String expectedAud, String expectedScope) throws Exception {
        assertNotNull("Auth token should not be null", authToken);
        
        // Parse JWT
        JWSInput jws = new JWSInput(authToken);
        
        // Verify type header
        assertEquals("Token type should be auth+jwt", "auth+jwt", jws.getHeader().getType());
        
        // Parse token claims
        AAuthToken token = jws.readJsonContent(AAuthToken.class);
        
        // Verify required claims
        assertNotNull("Issuer should be set", token.getIssuer());
        assertTrue("Issuer should contain realm", token.getIssuer().contains("/realms/" + TEST_REALM));
        
        assertNotNull("Audience should be set", token.getAudience());
        assertEquals("Audience should match", expectedAud, token.getAudience()[0]);
        
        if (expectedAgent != null && !expectedAgent.equals(expectedAud)) {
            assertEquals("Agent should match", expectedAgent, token.getAgent());
        }
        
        assertNotNull("Expiration should be set", token.getExp());
        assertTrue("Expiration should be in the future", token.getExp() > Time.currentTime());
        
        assertNotNull("Issued at should be set", token.getIat());
        
        // Verify cnf.jwk claim
        assertNotNull("CNF claim should be present", token.getCnf());
        assertNotNull("CNF JWK should be present", token.getCnf().getJwk());
        
        // Verify scope if provided
        if (expectedScope != null) {
            assertEquals("Scope should match", expectedScope, token.getScope());
        }
    }
}

