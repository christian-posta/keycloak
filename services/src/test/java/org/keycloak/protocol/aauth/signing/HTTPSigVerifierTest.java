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

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.Time;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.services.resteasy.HttpRequestImpl;
import org.keycloak.util.JsonSerialization;

import org.jboss.resteasy.mock.MockHttpRequest;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * End-to-end tests for HTTPSigVerifier
 */
public class HTTPSigVerifierTest {

    private KeycloakSession session;
    private Map<String, String> httpResponses;
    private Map<String, Object> sessionAttributes;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
    }

    @Before
    public void setUp() {
        httpResponses = new HashMap<>();
        sessionAttributes = new HashMap<>();
        
        // Create a mock KeycloakSession using Proxy
        session = (KeycloakSession) Proxy.newProxyInstance(
            HTTPSigVerifierTest.class.getClassLoader(),
            new Class[]{KeycloakSession.class},
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getProvider":
                        if (args.length > 0 && args[0] == HttpClientProvider.class) {
                            return createMockHttpClientProvider();
                        }
                        return null;
                    case "setAttribute":
                        if (args.length >= 2) {
                            sessionAttributes.put((String) args[0], args[1]);
                        }
                        return null;
                    case "getAttribute":
                        if (args.length >= 1) {
                            return sessionAttributes.get(args[0]);
                        }
                        return null;
                    default:
                        return null;
                }
            }
        );
    }

    private HttpClientProvider createMockHttpClientProvider() {
        return new HttpClientProvider() {
            @Override
            public String getString(String uri) throws java.io.IOException {
                String response = httpResponses.get(uri);
                if (response == null) {
                    throw new java.io.IOException("No response configured for: " + uri);
                }
                return response;
            }

            @Override
            public java.io.InputStream getInputStream(String uri) throws java.io.IOException {
                String response = httpResponses.get(uri);
                if (response == null) {
                    throw new java.io.IOException("No response configured for: " + uri);
                }
                return new java.io.ByteArrayInputStream(response.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }

            @Override
            public org.apache.http.impl.client.CloseableHttpClient getHttpClient() {
                return null;
            }

            @Override
            public int postText(String uri, String text) throws java.io.IOException {
                return 0;
            }

            @Override
            public void close() {
            }
        };
    }

    private KeyPair generateEd25519KeyPair() throws Exception {
        return CryptoIntegration.getProvider().getKeyPairGen("Ed25519").generateKeyPair();
    }

    /**
     * Create a signed HTTP request with hwk scheme.
     */
    private HttpRequest createSignedHwkRequest(KeyPair keyPair, String method, String path) throws Exception {
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + path);
        
        MockHttpRequest mockRequest = MockHttpRequest.create(method, baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Create Signature-Key header with hwk scheme
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        String xValue;
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            xValue = ((org.keycloak.jose.jwk.OKPPublicJWK) jwk).getX();
        } else {
            xValue = (String) jwk.getOtherClaims().get("x");
        }
        String signatureKey = String.format("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"%s\";kid=\"%s\"",
            xValue, kid);
        mockRequest.header("Signature-Key", signatureKey);
        
        // Create Signature-Input header
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        
        // Build signature base
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(
            new HttpRequestImpl(mockRequest), signatureInput, "sig");
        
        // Sign the signature base
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = 
            new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        
        byte[] signatureBytes = signer.sign(signatureBase);
        String base64Signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        
        // Create Signature header
        String signature = "sig=:" + base64Signature + ":";
        mockRequest.header("Signature", signature);
        
        return new HttpRequestImpl(mockRequest);
    }

    /**
     * Create a signed HTTP request with jwks scheme (Mode 1: direct JWKS URL).
     */
    private HttpRequest createSignedJwksRequest(KeyPair keyPair, String method, String path, String jwksUrl) throws Exception {
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + path);
        
        MockHttpRequest mockRequest = MockHttpRequest.create(method, baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Setup JWKS response
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        String jwksJson = createJWKSJson(keyPair.getPublic(), kid);
        httpResponses.put(jwksUrl, jwksJson);
        
        // Create Signature-Key header with jwks scheme
        String signatureKey = String.format("sig=jwks;jwks=\"%s\";kid=\"%s\"", jwksUrl, kid);
        mockRequest.header("Signature-Key", signatureKey);
        
        // Create Signature-Input header
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        
        // Build signature base
        byte[] signatureBase = SignatureBaseBuilder.buildSignatureBase(
            new HttpRequestImpl(mockRequest), signatureInput, "sig");
        
        // Sign the signature base
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = 
            new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        
        byte[] signatureBytes = signer.sign(signatureBase);
        String base64Signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        
        // Create Signature header
        String signature = "sig=:" + base64Signature + ":";
        mockRequest.header("Signature", signature);
        
        return new HttpRequestImpl(mockRequest);
    }

    private String createJWKSJson(java.security.PublicKey publicKey, String kid) throws Exception {
        JWK jwk = JWKBuilder.create().kid(kid).okp(publicKey);
        org.keycloak.jose.jwk.JSONWebKeySet jwks = new org.keycloak.jose.jwk.JSONWebKeySet();
        jwks.setKeys(new JWK[]{jwk});
        return JsonSerialization.writeValueAsString(jwks);
    }

    @Test
    public void testVerifyValidHwkSignature() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        HttpRequest request = createSignedHwkRequest(keyPair, "POST", "/protocol/aauth/token");
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        HTTPSigVerifier.VerificationResult result = verifier.verify(request);
        
        assertNotNull("Verification result should not be null", result);
        assertNotNull("Public key should not be null", result.getPublicKey());
        assertEquals("Scheme should be hwk", "hwk", result.getScheme());
        // Agent ID should be null for hwk scheme (pseudonymous)
        assertNull("Agent ID should be null for hwk scheme", result.getAgentId());
    }

    @Test
    public void testVerifyValidJwksSignature() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        String jwksUrl = "https://agent.example.com/jwks.json";
        HttpRequest request = createSignedJwksRequest(keyPair, "POST", "/protocol/aauth/token", jwksUrl);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        HTTPSigVerifier.VerificationResult result = verifier.verify(request);
        
        assertNotNull("Verification result should not be null", result);
        assertNotNull("Public key should not be null", result.getPublicKey());
        assertEquals("Scheme should be jwks", "jwks", result.getScheme());
        // Agent ID should be null for Mode 1 (direct JWKS URL)
        assertNull("Agent ID should be null for jwks Mode 1", result.getAgentId());
    }

    @Test
    public void testRejectMissingSignatureKeyHeader() throws Exception {
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + "/protocol/aauth/token");
        
        MockHttpRequest mockRequest = MockHttpRequest.create("POST", baseUri, requestUri);
        mockRequest.header("Host", host);
        // Don't add Signature-Key header
        
        HttpRequest request = new HttpRequestImpl(mockRequest);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        try {
            verifier.verify(request);
            fail("Should throw SignatureVerificationException for missing Signature-Key header");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention Signature-Key", e.getMessage().contains("Signature-Key"));
        }
    }

    @Test
    public void testRejectMissingSignatureInputHeader() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + "/protocol/aauth/token");
        
        MockHttpRequest mockRequest = MockHttpRequest.create("POST", baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Add Signature-Key but not Signature-Input
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        String xValue;
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            xValue = ((org.keycloak.jose.jwk.OKPPublicJWK) jwk).getX();
        } else {
            xValue = (String) jwk.getOtherClaims().get("x");
        }
        String signatureKey = String.format("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"%s\";kid=\"%s\"",
            xValue, kid);
        mockRequest.header("Signature-Key", signatureKey);
        // Don't add Signature-Input header
        
        HttpRequest request = new HttpRequestImpl(mockRequest);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        try {
            verifier.verify(request);
            fail("Should throw SignatureVerificationException for missing Signature-Input header");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention Signature-Input", e.getMessage().contains("Signature-Input"));
        }
    }

    @Test
    public void testRejectMissingSignatureHeader() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + "/protocol/aauth/token");
        
        MockHttpRequest mockRequest = MockHttpRequest.create("POST", baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Add Signature-Key and Signature-Input but not Signature
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        String xValue;
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            xValue = ((org.keycloak.jose.jwk.OKPPublicJWK) jwk).getX();
        } else {
            xValue = (String) jwk.getOtherClaims().get("x");
        }
        String signatureKey = String.format("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"%s\";kid=\"%s\"",
            xValue, kid);
        mockRequest.header("Signature-Key", signatureKey);
        
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        // Don't add Signature header
        
        HttpRequest request = new HttpRequestImpl(mockRequest);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        try {
            verifier.verify(request);
            fail("Should throw SignatureVerificationException for missing Signature header");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention Signature", e.getMessage().contains("Signature"));
        }
    }

    @Test
    public void testRejectInvalidSignature() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + "/protocol/aauth/token");
        
        MockHttpRequest mockRequest = MockHttpRequest.create("POST", baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Create Signature-Key header
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        String xValue;
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            xValue = ((org.keycloak.jose.jwk.OKPPublicJWK) jwk).getX();
        } else {
            xValue = (String) jwk.getOtherClaims().get("x");
        }
        String signatureKey = String.format("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"%s\";kid=\"%s\"",
            xValue, kid);
        mockRequest.header("Signature-Key", signatureKey);
        
        // Create Signature-Input header
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        
        // Create invalid signature (wrong bytes)
        byte[] invalidSignature = new byte[]{1, 2, 3, 4, 5};
        String base64Signature = Base64.getUrlEncoder().withoutPadding().encodeToString(invalidSignature);
        String signature = "sig=:" + base64Signature + ":";
        mockRequest.header("Signature", signature);
        
        HttpRequest request = new HttpRequestImpl(mockRequest);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        try {
            verifier.verify(request);
            fail("Should throw SignatureVerificationException for invalid signature");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention signature verification", 
                e.getMessage().contains("verification") || e.getMessage().contains("Signature"));
        }
    }

    @Test
    public void testRejectSignatureLabelMismatch() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + "/protocol/aauth/token");
        
        MockHttpRequest mockRequest = MockHttpRequest.create("POST", baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Create Signature-Key header with label "sig"
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        String xValue;
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            xValue = ((org.keycloak.jose.jwk.OKPPublicJWK) jwk).getX();
        } else {
            xValue = (String) jwk.getOtherClaims().get("x");
        }
        String signatureKey = String.format("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"%s\";kid=\"%s\"",
            xValue, kid);
        mockRequest.header("Signature-Key", signatureKey);
        
        // Create Signature-Input header with label "sig"
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        
        // Create Signature header with different label "wrong"
        byte[] signatureBytes = new byte[]{1, 2, 3};
        String base64Signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        String signature = "wrong=:" + base64Signature + ":"; // Wrong label
        mockRequest.header("Signature", signature);
        
        HttpRequest request = new HttpRequestImpl(mockRequest);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        try {
            verifier.verify(request);
            fail("Should throw SignatureVerificationException for label mismatch");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention label mismatch", 
                e.getMessage().contains("label") || e.getMessage().contains("mismatch"));
        }
    }

    @Test
    public void testRejectMalformedSignatureKeyHeader() throws Exception {
        String host = "keycloak.example.com";
        String baseUrl = "https://" + host;
        URI baseUri = URI.create(baseUrl);
        URI requestUri = URI.create(baseUrl + "/protocol/aauth/token");
        
        MockHttpRequest mockRequest = MockHttpRequest.create("POST", baseUri, requestUri);
        mockRequest.header("Host", host);
        
        // Create malformed Signature-Key header
        mockRequest.header("Signature-Key", "invalid-format");
        
        long created = Time.currentTime();
        String signatureInput = String.format("sig=(\"@method\" \"@authority\" \"@path\");created=%d", created);
        mockRequest.header("Signature-Input", signatureInput);
        
        String signature = "sig=:dGVzdA==:";
        mockRequest.header("Signature", signature);
        
        HttpRequest request = new HttpRequestImpl(mockRequest);
        
        HTTPSigVerifier verifier = new HTTPSigVerifier(session);
        try {
            verifier.verify(request);
            fail("Should throw SignatureVerificationException for malformed Signature-Key header");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention Signature-Key", e.getMessage().contains("Signature-Key"));
        }
    }
}

