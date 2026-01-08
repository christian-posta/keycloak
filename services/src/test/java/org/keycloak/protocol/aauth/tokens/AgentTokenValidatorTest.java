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
package org.keycloak.protocol.aauth.tokens;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.Time;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.metadata.AgentMetadata;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;
import org.keycloak.util.JsonSerialization;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for AgentTokenValidator
 */
public class AgentTokenValidatorTest {

    private static ResteasyKeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private Map<String, String> httpResponses;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
    }

    @Before
    public void setUp() {
        session = new ResteasyKeycloakSession(sessionFactory) {
            @Override
            public <T extends org.keycloak.provider.Provider> T getProvider(Class<T> clazz) {
                if (clazz == HttpClientProvider.class) {
                    @SuppressWarnings("unchecked")
                    T provider = (T) createMockHttpClientProvider();
                    return provider;
                }
                return super.getProvider(clazz);
            }
        };
        httpResponses = new HashMap<>();
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
     * Create a valid agent token with cnf.jwk claim.
     */
    private String createAgentToken(KeyPair signingKeyPair, KeyPair cnfKeyPair, String agentId, String delegateId) throws Exception {
        // Create JWK for cnf.jwk
        JWK cnfJwk = JWKBuilder.create().okp(cnfKeyPair.getPublic());
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", JsonSerialization.mapper.convertValue(cnfJwk, Map.class));

        // Create token claims
        JsonWebToken token = new JsonWebToken();
        token.issuer(agentId);
        token.subject(delegateId);
        long now = Time.currentTime();
        token.exp(now + 3600L); // 1 hour from now
        token.iat(now);
        
        // Add cnf claim
        token.setOtherClaims("cnf", cnf);

        // Sign token
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        String signedToken = new JWSBuilder()
                .type("agent+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);

        return signedToken;
    }

    private String createAgentMetadataJson(String agentId, String jwksUri) throws Exception {
        AgentMetadata metadata = new AgentMetadata();
        metadata.setAgent(agentId);
        metadata.setJwksUri(jwksUri);
        return JsonSerialization.writeValueAsString(metadata);
    }

    private String createJWKSJson(java.security.PublicKey publicKey, String kid) throws Exception {
        JWK jwk = JWKBuilder.create().kid(kid).okp(publicKey);
        org.keycloak.jose.jwk.JSONWebKeySet jwks = new org.keycloak.jose.jwk.JSONWebKeySet();
        jwks.setKeys(new JWK[]{jwk});
        return JsonSerialization.writeValueAsString(jwks);
    }

    @Test
    public void testValidateValidAgentToken() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create agent token
        String agentToken = createAgentToken(signingKeyPair, cnfKeyPair, agentId, delegateId);
        
        // Setup HTTP responses
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token
        AgentTokenValidator validator = new AgentTokenValidator(session);
        Map<String, Object> cnf = validator.validateAndExtractCnf(agentToken);
        
        // Verify cnf claim is returned
        assertNotNull("cnf claim should not be null", cnf);
        assertNotNull("cnf.jwk should not be null", cnf.get("jwk"));
    }

    @Test
    public void testRejectExpiredToken() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create expired token
        JWK cnfJwk = JWKBuilder.create().okp(cnfKeyPair.getPublic());
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", JsonSerialization.mapper.convertValue(cnfJwk, Map.class));

        JsonWebToken token = new JsonWebToken();
        token.issuer(agentId);
        token.subject(delegateId);
        long now = Time.currentTime();
        token.exp(now - 3600L); // Expired 1 hour ago
        token.iat(now - 7200L);
        token.setOtherClaims("cnf", cnf);

        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        String agentToken = new JWSBuilder()
                .type("agent+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException for expired token");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention expired", e.getMessage().contains("expired"));
        }
    }

    @Test
    public void testRejectMissingCnfJwkClaim() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create token without cnf.jwk
        JsonWebToken token = new JsonWebToken();
        token.issuer(agentId);
        token.subject(delegateId);
        long now = Time.currentTime();
        token.exp(now + 3600L);
        token.iat(now);
        // Don't add cnf claim
        
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        String agentToken = new JWSBuilder()
                .type("agent+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException for missing cnf claim");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention cnf", e.getMessage().contains("cnf"));
        }
    }

    @Test
    public void testRejectInvalidIssuer() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create token with missing issuer
        JWK cnfJwk = JWKBuilder.create().okp(cnfKeyPair.getPublic());
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", JsonSerialization.mapper.convertValue(cnfJwk, Map.class));

        JsonWebToken token = new JsonWebToken();
        // Don't set issuer
        token.subject(delegateId);
        long now = Time.currentTime();
        token.exp(now + 3600L);
        token.iat(now);
        token.setOtherClaims("cnf", cnf);

        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        String agentToken = new JWSBuilder()
                .type("agent+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException for missing issuer");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention iss", e.getMessage().contains("iss"));
        }
    }

    @Test
    public void testRejectMissingSubClaim() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create token without sub claim
        JWK cnfJwk = JWKBuilder.create().okp(cnfKeyPair.getPublic());
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", JsonSerialization.mapper.convertValue(cnfJwk, Map.class));

        JsonWebToken token = new JsonWebToken();
        token.issuer(agentId);
        // Don't set subject
        long now = Time.currentTime();
        token.exp(now + 3600L);
        token.iat(now);
        token.setOtherClaims("cnf", cnf);

        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        String agentToken = new JWSBuilder()
                .type("agent+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException for missing sub claim");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention sub", e.getMessage().contains("sub"));
        }
    }

    @Test
    public void testRejectInvalidTokenType() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create token with wrong typ
        JWK cnfJwk = JWKBuilder.create().okp(cnfKeyPair.getPublic());
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", JsonSerialization.mapper.convertValue(cnfJwk, Map.class));

        JsonWebToken token = new JsonWebToken();
        token.issuer(agentId);
        token.subject(delegateId);
        long now = Time.currentTime();
        token.exp(now + 3600L);
        token.iat(now);
        token.setOtherClaims("cnf", cnf);

        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
        keyWrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
        org.keycloak.crypto.AsymmetricSignatureSignerContext signer = new org.keycloak.crypto.AsymmetricSignatureSignerContext(keyWrapper);
        String agentToken = new JWSBuilder()
                .type("auth+jwt") // Wrong type
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException for invalid token type");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention token type", 
                e.getMessage().contains("agent+jwt") || e.getMessage().contains("type"));
        }
    }

    @Test
    public void testRejectMetadataFetchFailure() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        
        // Create agent token
        String agentToken = createAgentToken(signingKeyPair, cnfKeyPair, agentId, delegateId);
        
        // Don't setup HTTP responses - simulate metadata fetch failure
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException when metadata fetch fails");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention metadata", e.getMessage().contains("metadata"));
        }
    }

    @Test
    public void testRejectJWKSFetchFailure() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create agent token
        String agentToken = createAgentToken(signingKeyPair, cnfKeyPair, agentId, delegateId);
        
        // Setup metadata response but not JWKS response
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        httpResponses.put(metadataUrl, metadataJson);
        // Don't add jwksUri to httpResponses
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException when JWKS fetch fails");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention JWKS", e.getMessage().contains("JWKS"));
        }
    }

    @Test
    public void testRejectKeyNotFoundInJWKS() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create agent token
        String agentToken = createAgentToken(signingKeyPair, cnfKeyPair, agentId, delegateId);
        
        // Setup HTTP responses with wrong kid in JWKS
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        String wrongKid = "wrong-key-id";
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), wrongKid); // Wrong kid
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Validate token - should fail
        AgentTokenValidator validator = new AgentTokenValidator(session);
        try {
            validator.validateAndExtractCnf(agentToken);
            fail("Should throw SignatureVerificationException when key with kid is not found");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention kid not found", 
                e.getMessage().contains("not found") || e.getMessage().contains(kid));
        }
    }
}

