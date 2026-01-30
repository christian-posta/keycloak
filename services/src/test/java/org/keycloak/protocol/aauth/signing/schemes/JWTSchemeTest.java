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
package org.keycloak.protocol.aauth.signing.schemes;

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
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.metadata.AgentMetadata;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for JWTScheme
 */
public class JWTSchemeTest {

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
            JWTSchemeTest.class.getClassLoader(),
            new Class[]{KeycloakSession.class},
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getProvider":
                        if (args.length > 0 && args[0] == HttpClientProvider.class) {
                            return createMockHttpClientProvider();
                        }
                        if (args.length > 1 && args[0] == org.keycloak.crypto.SignatureProvider.class) {
                            String algorithm = (String) args[1];
                            if ("Ed25519".equals(algorithm) || "EdDSA".equals(algorithm)) {
                                return createMockSignatureProvider();
                            }
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
                    case "getContext":
                        // Return null context - AuthTokenValidator handles this gracefully
                        return null;
                    default:
                        return null;
                }
            }
        );
    }

    private org.keycloak.crypto.SignatureProvider createMockSignatureProvider() {
        return new org.keycloak.crypto.SignatureProvider() {
            @Override
            public org.keycloak.crypto.SignatureSignerContext signer() throws org.keycloak.crypto.SignatureException {
                return null;
            }
            
            @Override
            public org.keycloak.crypto.SignatureSignerContext signer(KeyWrapper key) throws org.keycloak.crypto.SignatureException {
                return null;
            }
            
            @Override
            public org.keycloak.crypto.SignatureVerifierContext verifier(String kid) throws org.keycloak.common.VerificationException {
                return null;
            }
            
            @Override
            public org.keycloak.crypto.SignatureVerifierContext verifier(KeyWrapper key) throws org.keycloak.common.VerificationException {
                return new org.keycloak.crypto.SignatureVerifierContext() {
                    @Override
                    public String getKid() {
                        return key.getKid();
                    }
                    
                    @Override
                    public String getAlgorithm() {
                        return key.getAlgorithm();
                    }
                    
                    @Override
                    public boolean verify(byte[] data, byte[] signature) throws org.keycloak.common.VerificationException {
                        try {
                            java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
                            sig.initVerify((java.security.PublicKey) key.getPublicKey());
                            sig.update(data);
                            return sig.verify(signature);
                        } catch (Exception e) {
                            throw new org.keycloak.common.VerificationException("Signature verification failed", e);
                        }
                    }
                };
            }
            
            @Override
            public boolean isAsymmetricAlgorithm() {
                return true;
            }
        };
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
     * Create an agent+jwt token with cnf.jwk claim.
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

        // Sign token using SignatureSignerContext
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(Algorithm.Ed25519);
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(keyWrapper);
        String signedToken = new JWSBuilder()
                .type("agent+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);

        return signedToken;
    }

    /**
     * Create an auth+jwt token with cnf.jwk claim.
     */
    private String createAuthToken(KeyPair signingKeyPair, KeyPair cnfKeyPair, String authServerId, String agentId, String resourceId) throws Exception {
        // Create JWK for cnf.jwk
        JWK cnfJwk = JWKBuilder.create().okp(cnfKeyPair.getPublic());
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jwk", JsonSerialization.mapper.convertValue(cnfJwk, Map.class));

        // Create token claims
        JsonWebToken token = new JsonWebToken();
        token.issuer(authServerId);
        token.audience(resourceId);
        long now = Time.currentTime();
        token.exp(now + 3600L); // 1 hour from now
        token.iat(now);
        
        // Add agent and cnf claims
        token.setOtherClaims("agent", agentId);
        token.setOtherClaims("cnf", cnf);

        // Sign token using SignatureSignerContext
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(Algorithm.Ed25519);
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(keyWrapper);
        String signedToken = new JWSBuilder()
                .type("auth+jwt")
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

    private String createJWKSJson(PublicKey publicKey, String kid) throws Exception {
        JWK jwk = JWKBuilder.create().kid(kid).okp(publicKey);
        org.keycloak.jose.jwk.JSONWebKeySet jwks = new org.keycloak.jose.jwk.JSONWebKeySet();
        jwks.setKeys(new JWK[]{jwk});
        return JsonSerialization.writeValueAsString(jwks);
    }

    @Test
    public void testExtractPublicKeyFromAgentToken() throws Exception {
        // Generate key pairs
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        PublicKey expectedPublicKey = cnfKeyPair.getPublic();
        
        String agentId = "https://agent.example.com";
        String delegateId = "https://delegate.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Create agent token
        String agentToken = createAgentToken(signingKeyPair, cnfKeyPair, agentId, delegateId);
        
        // Setup HTTP responses for agent token validation
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Create Signature-Key header
        String signatureKeyHeader = "sig=jwt;jwt=\"" + agentToken + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key
        JWTScheme scheme = new JWTScheme(session);
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testExtractPublicKeyFromAuthToken() throws Exception {
        // Generate key pairs
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        PublicKey expectedPublicKey = cnfKeyPair.getPublic();
        
        String authServerId = "https://auth.example.com";
        String agentId = "https://agent.example.com";
        String resourceId = "https://resource.example.com";
        
        // Set up mock JWKS response for auth server (for JWT signature verification)
        String authServerJwksUri = authServerId + "/protocol/openid-connect/certs";
        String signingKid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        String authServerJwksJson = createJWKSJson(signingKeyPair.getPublic(), signingKid);
        httpResponses.put(authServerJwksUri, authServerJwksJson);
        
        // Create auth token
        String authToken = createAuthToken(signingKeyPair, cnfKeyPair, authServerId, agentId, resourceId);
        
        // Create Signature-Key header
        String signatureKeyHeader = "sig=jwt;jwt=\"" + authToken + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key
        JWTScheme scheme = new JWTScheme(session);
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testGetAlgorithmFromAgentToken() throws Exception {
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
        
        // Create Signature-Key header
        String signatureKeyHeader = "sig=jwt;jwt=\"" + agentToken + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Discover key first (to cache it)
        JWTScheme scheme = new JWTScheme(session);
        scheme.discoverPublicKey(keyParser);
        
        // Get algorithm
        String algorithm = scheme.getAlgorithm(keyParser);
        assertNotNull("Algorithm should not be null", algorithm);
        // Should be Ed25519 for EdDSA algorithm
        assertEquals("Algorithm should be Ed25519", "Ed25519", algorithm);
    }

    @Test
    public void testGetAgentIdFromAgentToken() throws Exception {
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
        
        // Create Signature-Key header
        String signatureKeyHeader = "sig=jwt;jwt=\"" + agentToken + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Get agent ID
        JWTScheme scheme = new JWTScheme(session);
        String extractedAgentId = scheme.getAgentId(keyParser);
        
        assertEquals("Agent ID should match issuer", agentId, extractedAgentId);
    }

    @Test
    public void testGetAgentIdFromAuthToken() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        KeyPair cnfKeyPair = generateEd25519KeyPair();
        String authServerId = "https://auth.example.com";
        String agentId = "https://agent.example.com";
        String resourceId = "https://resource.example.com";
        
        // Create auth token
        String authToken = createAuthToken(signingKeyPair, cnfKeyPair, authServerId, agentId, resourceId);
        
        // Create Signature-Key header
        String signatureKeyHeader = "sig=jwt;jwt=\"" + authToken + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Get agent ID
        JWTScheme scheme = new JWTScheme(session);
        String extractedAgentId = scheme.getAgentId(keyParser);
        
        assertEquals("Agent ID should match agent claim", agentId, extractedAgentId);
    }

    @Test
    public void testMissingJwtParameter() throws Exception {
        String signatureKeyHeader = "sig=jwt";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWTScheme scheme = new JWTScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when jwt parameter is missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention jwt", e.getMessage().contains("jwt"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        }
    }

    @Test
    public void testInvalidJWTFormat() throws Exception {
        String signatureKeyHeader = "sig=jwt;jwt=\"invalid.jwt.format\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWTScheme scheme = new JWTScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw exception for invalid JWT format");
        } catch (SignatureVerificationException e) {
            // Expected - validator throws this
        } catch (org.keycloak.jose.jws.JWSInputException e) {
            // Expected - JWSInput throws this when parsing invalid JWT
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other parsing exceptions
        }
    }

    @Test
    public void testUnsupportedJWTType() throws Exception {
        // Create a token with unsupported typ
        KeyPair keyPair = generateEd25519KeyPair();
        JsonWebToken token = new JsonWebToken();
        token.issuer("https://test.example.com");
        long now = Time.currentTime();
        token.exp(now + 3600L);
        
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(keyPair.getPublic());
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setCurve(Algorithm.Ed25519);
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(keyWrapper);
        String signedToken = new JWSBuilder()
                .type("unsupported+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        String signatureKeyHeader = "sig=jwt;jwt=\"" + signedToken + "\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWTScheme scheme = new JWTScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException for unsupported JWT type");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention unsupported type", 
                e.getMessage().contains("Unsupported") || e.getMessage().contains("unsupported"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testMissingCnfJwkInAgentToken() throws Exception {
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
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(Algorithm.Ed25519);
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(keyWrapper);
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
        
        String signatureKeyHeader = "sig=jwt;jwt=\"" + agentToken + "\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWTScheme scheme = new JWTScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when cnf.jwk is missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention cnf.jwk", 
                e.getMessage().contains("cnf.jwk") || e.getMessage().contains("cnf"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testMissingCnfJwkInAuthToken() throws Exception {
        KeyPair signingKeyPair = generateEd25519KeyPair();
        String authServerId = "https://auth.example.com";
        String agentId = "https://agent.example.com";
        String resourceId = "https://resource.example.com";
        
        // Set up mock JWKS response for auth server (for JWT signature verification)
        String kid = org.keycloak.common.util.KeyUtils.createKeyId(signingKeyPair.getPublic());
        String authServerJwksUri = authServerId + "/protocol/openid-connect/certs";
        String authServerJwksJson = createJWKSJson(signingKeyPair.getPublic(), kid);
        httpResponses.put(authServerJwksUri, authServerJwksJson);
        
        // Create token without cnf.jwk
        JsonWebToken token = new JsonWebToken();
        token.issuer(authServerId);
        token.audience(resourceId);
        long now = Time.currentTime();
        token.exp(now + 3600L);
        token.iat(now);
        
        token.setOtherClaims("agent", agentId);
        // Don't add cnf claim
        
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setAlgorithm(Algorithm.EdDSA);
        keyWrapper.setKid(kid);
        keyWrapper.setPrivateKey(signingKeyPair.getPrivate());
        keyWrapper.setPublicKey(signingKeyPair.getPublic());
        keyWrapper.setCurve(Algorithm.Ed25519);
        AsymmetricSignatureSignerContext signer = new AsymmetricSignatureSignerContext(keyWrapper);
        String authToken = new JWSBuilder()
                .type("auth+jwt")
                .kid(kid)
                .jsonContent(token)
                .sign(signer);
        
        String signatureKeyHeader = "sig=jwt;jwt=\"" + authToken + "\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWTScheme scheme = new JWTScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when cnf.jwk is missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention cnf.jwk or cnf", 
                e.getMessage().contains("cnf.jwk") || e.getMessage().contains("cnf"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }
}

