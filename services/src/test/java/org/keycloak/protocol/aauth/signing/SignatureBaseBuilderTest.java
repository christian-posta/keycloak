/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.protocol.aauth.signing;

import org.jboss.resteasy.mock.MockHttpRequest;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureBaseException;
import org.keycloak.services.resteasy.HttpRequestImpl;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;

import java.net.URI;

import static org.junit.Assert.*;

/**
 * Unit tests for SignatureBaseBuilder
 */
public class SignatureBaseBuilderTest {

    private static ResteasyKeycloakSessionFactory sessionFactory;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
    }

    private HttpRequest createMockRequest(String method, String path, String query, String host, String contentType, String contentDigest, String signatureKey, String nonce) {
        String baseUrl = "https://" + (host != null ? host : "keycloak.example.com");
        String fullPath = path;
        if (query != null && !query.isEmpty()) {
            fullPath = path + "?" + query;
        }
        
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + fullPath);
        
        MockHttpRequest mockRequest = MockHttpRequest.create(method, baseUri, requestUri);
        
        if (host != null) {
            mockRequest.header("Host", host);
        }
        if (contentType != null) {
            mockRequest.header("Content-Type", contentType);
        }
        if (contentDigest != null) {
            mockRequest.header("Content-Digest", contentDigest);
        }
        if (signatureKey != null) {
            mockRequest.header("Signature-Key", signatureKey);
        }
        if (nonce != null) {
            mockRequest.header("Nonce", nonce);
        }
        
        return new HttpRequestImpl(mockRequest);
    }

    @Test
    public void testBuildSignatureBaseWithMethodAndPath() throws Exception {
        HttpRequest request = createMockRequest("POST", "/protocol/aauth/token", null, "keycloak.example.com", null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"@path\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        assertTrue("Should contain @method", baseString.contains("\"@method\": POST"));
        // The path should be extracted from getAbsolutePath().getPath()
        String expectedPath = request.getUri().getAbsolutePath().getPath();
        if (expectedPath == null || expectedPath.isEmpty()) {
            expectedPath = "/";
        }
        assertTrue("Should contain @path with value: " + expectedPath + ". Actual: " + baseString, 
            baseString.contains("\"@path\": " + expectedPath));
        assertTrue("Should contain signature-params", baseString.contains("@signature-params"));
        assertTrue("Should contain created", baseString.contains("created=1234567890"));
    }

    @Test
    public void testBuildSignatureBaseWithAuthority() throws Exception {
        HttpRequest request = createMockRequest("GET", "/api/data", null, "keycloak.example.com:8443", null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"@authority\" \"@path\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        assertTrue("Should contain @authority", baseString.contains("\"@authority\": keycloak.example.com:8443"));
    }

    @Test
    public void testBuildSignatureBaseWithQuery() throws Exception {
        HttpRequest request = createMockRequest("GET", "/api/data", "user=alice&limit=10", "keycloak.example.com", null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"@path\" \"@query\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        // Check for @query component
        assertTrue("Should contain @query. Actual: " + baseString, baseString.contains("\"@query\":"));
        // The query should be prefixed with "?"
        String expectedQuery = request.getUri().getRequestUri().getRawQuery();
        if (expectedQuery != null && !expectedQuery.isEmpty()) {
            assertTrue("Should contain query value: ?" + expectedQuery + ". Actual: " + baseString, 
                baseString.contains("?" + expectedQuery));
        }
    }

    @Test
    public void testBuildSignatureBaseWithContentType() throws Exception {
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", "application/json", null, null, null);
        String signatureInput = "sig=(\"@method\" \"@path\" \"content-type\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        assertTrue("Should contain content-type", baseString.contains("\"content-type\": application/json"));
    }

    @Test
    public void testBuildSignatureBaseWithContentDigest() throws Exception {
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", "application/json", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", null, null);
        String signatureInput = "sig=(\"@method\" \"@path\" \"content-digest\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        assertTrue("Should contain content-digest", baseString.contains("\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"));
    }

    @Test
    public void testBuildSignatureBaseWithSignatureKey() throws Exception {
        String signatureKey = "sig=(scheme=hwk kty=\"OKP\" crv=\"Ed25519\" x=\"test\")";
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", null, null, signatureKey, null);
        String signatureInput = "sig=(\"@method\" \"@path\" \"signature-key\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        assertTrue("Should contain signature-key", baseString.contains("\"signature-key\": " + signatureKey));
    }

    @Test
    public void testBuildSignatureBaseWithNonce() throws Exception {
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", null, null, null, "Y3VyaW91c2x5Y3VyaW91cw");
        String signatureInput = "sig=(\"@method\" \"@path\" \"nonce\");created=1234567890;nonce=\"Y3VyaW91c2x5Y3VyaW91cw\"";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        assertTrue("Should contain nonce", baseString.contains("\"nonce\": Y3VyaW91c2x5Y3VyaW91cw"));
        assertTrue("Should contain nonce in signature-params", baseString.contains("nonce="));
    }

    @Test
    public void testBuildSignatureBaseWithAllComponents() throws Exception {
        String signatureKey = "sig=(scheme=hwk kty=\"OKP\" crv=\"Ed25519\" x=\"test\")";
        HttpRequest request = createMockRequest(
            "POST", 
            "/api/data", 
            "confirm=true", 
            "keycloak.example.com:8443",
            "application/json",
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
            signatureKey,
            "test-nonce-123"
        );
        String signatureInput = "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-type\" \"content-digest\" \"signature-key\" \"nonce\");created=1234567890;nonce=\"test-nonce-123\"";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        // Verify all components are present
        assertTrue("Should contain @method", baseString.contains("\"@method\": POST"));
        assertTrue("Should contain @authority", baseString.contains("\"@authority\": keycloak.example.com:8443"));
        // Check @path with actual path value
        String expectedPath = request.getUri().getAbsolutePath().getPath();
        if (expectedPath == null || expectedPath.isEmpty()) {
            expectedPath = "/";
        }
        assertTrue("Should contain @path. Expected: " + expectedPath + ", Actual: " + baseString, 
            baseString.contains("\"@path\": " + expectedPath));
        // Check @query
        String expectedQuery = request.getUri().getRequestUri().getRawQuery();
        if (expectedQuery != null && !expectedQuery.isEmpty()) {
            assertTrue("Should contain @query. Expected: ?" + expectedQuery + ", Actual: " + baseString, 
                baseString.contains("\"@query\": ?" + expectedQuery));
        }
        assertTrue("Should contain content-type", baseString.contains("\"content-type\": application/json"));
        assertTrue("Should contain content-digest", baseString.contains("\"content-digest\":"));
        assertTrue("Should contain signature-key", baseString.contains("\"signature-key\":"));
        assertTrue("Should contain nonce", baseString.contains("\"nonce\": test-nonce-123"));
    }

    @Test
    public void testBuildSignatureBaseMissingRequiredComponent() {
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"content-type\");created=1234567890";
        
        try {
            SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
            fail("Should throw SignatureBaseException when required component is missing");
        } catch (SignatureBaseException e) {
            // Expected
            assertTrue("Error should mention Content-Type", e.getMessage().contains("Content-Type") || e.getMessage().contains("content-type"));
        }
    }

    @Test
    public void testBuildSignatureBaseMissingHostHeader() {
        HttpRequest request = createMockRequest("GET", "/api/data", null, null, null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"@authority\");created=1234567890";
        
        try {
            SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
            fail("Should throw SignatureBaseException when Host header is missing");
        } catch (SignatureBaseException e) {
            // Expected
            assertTrue("Error should mention Host", e.getMessage().contains("Host") || e.getMessage().contains("@authority"));
        }
    }

    @Test
    public void testBuildSignatureBaseEmptyPath() throws Exception {
        HttpRequest request = createMockRequest("GET", "", null, "keycloak.example.com", null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"@path\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        // Empty path should become "/"
        assertTrue("Should contain @path with /", baseString.contains("\"@path\": /"));
    }

    @Test
    public void testBuildSignatureBaseEmptyQuery() throws Exception {
        HttpRequest request = createMockRequest("GET", "/api/data", "", "keycloak.example.com", null, null, null, null);
        String signatureInput = "sig=(\"@method\" \"@path\" \"@query\");created=1234567890";
        
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
        String baseString = new String(signatureBase);
        
        // Empty query should become "?"
        assertTrue("Should contain @query with ?", baseString.contains("\"@query\": ?"));
    }

    @Test
    public void testBuildSignatureBaseInvalidSignatureInput() {
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", null, null, null, null);
        String signatureInput = "invalid-format";
        
        try {
            SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
            fail("Should throw SignatureBaseException for invalid Signature-Input format");
        } catch (SignatureBaseException e) {
            // Expected
        }
    }

    @Test
    public void testBuildSignatureBaseWrongLabel() {
        HttpRequest request = createMockRequest("POST", "/api/data", null, "keycloak.example.com", null, null, null, null);
        String signatureInput = "other=(\"@method\" \"@path\");created=1234567890";
        
        try {
            SignatureBaseBuilder.buildSignatureBase(request, signatureInput, "sig");
            fail("Should throw SignatureBaseException when signature label doesn't match");
        } catch (SignatureBaseException e) {
            // Expected
            assertTrue("Error should mention signature label", e.getMessage().contains("sig") || e.getMessage().contains("label"));
        }
    }

    @Test
    public void testCalculateContentDigestSha256() throws Exception {
        byte[] body = "Hello, World!".getBytes();
        String digest = SignatureBaseBuilder.calculateContentDigest(body, "sha-256");
        
        assertNotNull("Content-Digest should not be null", digest);
        assertTrue("Should start with sha-256=:", digest.startsWith("sha-256=:"));
        assertTrue("Should end with :", digest.endsWith(":"));
    }

    @Test
    public void testCalculateContentDigestSha512() throws Exception {
        byte[] body = "Hello, World!".getBytes();
        String digest = SignatureBaseBuilder.calculateContentDigest(body, "sha-512");
        
        assertNotNull("Content-Digest should not be null", digest);
        assertTrue("Should start with sha-512=:", digest.startsWith("sha-512=:"));
        assertTrue("Should end with :", digest.endsWith(":"));
    }

    @Test
    public void testCalculateContentDigestEmptyBody() throws Exception {
        byte[] body = new byte[0];
        String digest = SignatureBaseBuilder.calculateContentDigest(body, "sha-256");
        
        assertNull("Content-Digest should be null for empty body", digest);
    }

    @Test
    public void testCalculateContentDigestUnsupportedAlgorithm() {
        byte[] body = "Hello, World!".getBytes();
        
        try {
            SignatureBaseBuilder.calculateContentDigest(body, "md5");
            fail("Should throw SignatureBaseException for unsupported algorithm");
        } catch (SignatureBaseException e) {
            // Expected
            assertTrue("Error should mention algorithm", e.getMessage().contains("algorithm") || e.getMessage().contains("md5"));
        }
    }
}

