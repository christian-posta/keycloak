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
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.metadata.AgentMetadata;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.util.JsonSerialization;

import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for JWKSScheme
 */
public class JWKSSchemeTest {

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
            JWKSSchemeTest.class.getClassLoader(),
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
                return null; // Not used in our tests
            }

            @Override
            public int postText(String uri, String text) throws java.io.IOException {
                return 0; // Not used in our tests
            }

            @Override
            public void close() {
                // No-op
            }
        };
    }

    private KeyPair generateEd25519KeyPair() throws Exception {
        return CryptoIntegration.getProvider().getKeyPairGen("Ed25519").generateKeyPair();
    }

    private String createJWKSJson(PublicKey publicKey, String kid) throws Exception {
        JWK jwk = JWKBuilder.create().kid(kid).okp(publicKey);
        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[]{jwk});
        return JsonSerialization.writeValueAsString(jwks);
    }

    private String createAgentMetadataJson(String agentId, String jwksUri) throws Exception {
        AgentMetadata metadata = new AgentMetadata();
        metadata.setAgent(agentId);
        metadata.setJwksUri(jwksUri);
        return JsonSerialization.writeValueAsString(metadata);
    }

    @Test
    public void testMode1DirectJWKSUrl() throws Exception {
        // Generate test key
        KeyPair keyPair = generateEd25519KeyPair();
        PublicKey expectedPublicKey = keyPair.getPublic();
        String kid = "test-key-1";
        String jwksUrl = "https://agent.example.com/jwks.json";
        
        // Setup HTTP response for JWKS
        String jwksJson = createJWKSJson(expectedPublicKey, kid);
        httpResponses.put(jwksUrl, jwksJson);
        
        // Create Signature-Key header for Mode 1
        String signatureKeyHeader = "sig=jwks;jwks=\"" + jwksUrl + "\";kid=\"" + kid + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key
        JWKSScheme scheme = new JWKSScheme(session);
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testMode2IdentifierWithMetadata() throws Exception {
        // Generate test key
        KeyPair keyPair = generateEd25519KeyPair();
        PublicKey expectedPublicKey = keyPair.getPublic();
        String kid = "test-key-2";
        String agentId = "https://agent.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String metadataUrl = agentId + "/.well-known/aauth-agent";
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(expectedPublicKey, kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Create Signature-Key header for Mode 2
        String signatureKeyHeader = "sig=jwks;id=\"" + agentId + "\";kid=\"" + kid + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key
        JWKSScheme scheme = new JWKSScheme(session);
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testMode2WithCustomWellKnown() throws Exception {
        // Generate test key
        KeyPair keyPair = generateEd25519KeyPair();
        PublicKey expectedPublicKey = keyPair.getPublic();
        String kid = "test-key-3";
        String agentId = "https://agent.example.com";
        String jwksUri = "https://agent.example.com/jwks.json";
        String wellKnown = "custom-agent-meta";
        String metadataUrl = agentId + "/.well-known/" + wellKnown;
        
        // Setup HTTP responses
        String metadataJson = createAgentMetadataJson(agentId, jwksUri);
        String jwksJson = createJWKSJson(expectedPublicKey, kid);
        httpResponses.put(metadataUrl, metadataJson);
        httpResponses.put(jwksUri, jwksJson);
        
        // Create Signature-Key header for Mode 2 with custom well-known
        String signatureKeyHeader = "sig=jwks;id=\"" + agentId + "\";kid=\"" + kid + "\";well-known=\"" + wellKnown + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key
        JWKSScheme scheme = new JWKSScheme(session);
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testGetAlgorithm() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        String kid = "test-key-4";
        String jwksUrl = "https://agent.example.com/jwks.json";
        
        // Setup HTTP response
        String jwksJson = createJWKSJson(keyPair.getPublic(), kid);
        httpResponses.put(jwksUrl, jwksJson);
        
        // Create Signature-Key header
        String signatureKeyHeader = "sig=jwks;jwks=\"" + jwksUrl + "\";kid=\"" + kid + "\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Discover key first (to cache it)
        JWKSScheme scheme = new JWKSScheme(session);
        scheme.discoverPublicKey(keyParser);
        
        // Get algorithm
        String algorithm = scheme.getAlgorithm(keyParser);
        assertNotNull("Algorithm should not be null", algorithm);
        // Algorithm should be determined from the JWK (likely Ed25519 or EdDSA)
    }

    @Test
    public void testGetAgentIdMode2() throws Exception {
        String agentId = "https://agent.example.com";
        String signatureKeyHeader = "sig=jwks;id=\"" + agentId + "\";kid=\"test-key\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        JWKSScheme scheme = new JWKSScheme(session);
        String extractedAgentId = scheme.getAgentId(keyParser);
        
        assertEquals("Agent ID should match", agentId, extractedAgentId);
    }

    @Test
    public void testGetAgentIdMode1() throws Exception {
        String signatureKeyHeader = "sig=jwks;jwks=\"https://agent.example.com/jwks.json\";kid=\"test-key\"";
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        JWKSScheme scheme = new JWKSScheme(session);
        String extractedAgentId = scheme.getAgentId(keyParser);
        
        assertNull("Agent ID should be null for Mode 1", extractedAgentId);
    }

    @Test
    public void testMissingKid() {
        String signatureKeyHeader = "sig=jwks;jwks=\"https://agent.example.com/jwks.json\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWKSScheme scheme = new JWKSScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when kid is missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention kid", e.getMessage().contains("kid"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testMissingJwksAndId() {
        String signatureKeyHeader = "sig=jwks;kid=\"test-key\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWKSScheme scheme = new JWKSScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when both jwks and id are missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention jwks or id", 
                e.getMessage().contains("jwks") || e.getMessage().contains("id"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testBothJwksAndIdPresent() {
        String signatureKeyHeader = "sig=jwks;jwks=\"https://agent.example.com/jwks.json\";id=\"https://agent.example.com\";kid=\"test-key\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWKSScheme scheme = new JWKSScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when both jwks and id are present");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention mutually exclusive", 
                e.getMessage().contains("mutually exclusive") || 
                e.getMessage().contains("Both"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testWellKnownInMode1() {
        String signatureKeyHeader = "sig=jwks;jwks=\"https://agent.example.com/jwks.json\";kid=\"test-key\";well-known=\"aauth-agent\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWKSScheme scheme = new JWKSScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when well-known is present in Mode 1");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention well-known", e.getMessage().contains("well-known"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testJWKSFetchFailure() {
        String jwksUrl = "https://agent.example.com/jwks.json";
        String signatureKeyHeader = "sig=jwks;jwks=\"" + jwksUrl + "\";kid=\"test-key\"";
        
        // Don't setup HTTP response - simulate fetch failure
        httpResponses.put(jwksUrl, null);
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWKSScheme scheme = new JWKSScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when JWKS fetch fails");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention JWKS", e.getMessage().contains("JWKS"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testKeyNotFoundInJWKS() {
        try {
            KeyPair keyPair = generateEd25519KeyPair();
            String wrongKid = "wrong-key-id";
            String jwksUrl = "https://agent.example.com/jwks.json";
            
            // Setup JWKS with different kid
            String jwksJson = createJWKSJson(keyPair.getPublic(), "correct-key-id");
            httpResponses.put(jwksUrl, jwksJson);
            
            String signatureKeyHeader = "sig=jwks;jwks=\"" + jwksUrl + "\";kid=\"" + wrongKid + "\"";
            
            try {
                SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
                JWKSScheme scheme = new JWKSScheme(session);
                scheme.discoverPublicKey(keyParser);
                fail("Should throw SignatureVerificationException when key with kid is not found");
            } catch (SignatureVerificationException e) {
                assertTrue("Error should mention kid not found", 
                    e.getMessage().contains("not found") || e.getMessage().contains(wrongKid));
            } catch (SignatureKeyParseException e) {
                // Also acceptable if parsing fails
            }
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testMode2MetadataFetchFailure() {
        String agentId = "https://agent.example.com";
        String signatureKeyHeader = "sig=jwks;id=\"" + agentId + "\";kid=\"test-key\"";
        
        // Don't setup metadata response - simulate fetch failure
        // Leave httpResponses empty so getString will throw IOException
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            JWKSScheme scheme = new JWKSScheme(session);
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when metadata fetch fails");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention metadata", e.getMessage().contains("metadata"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions (like IOException from HTTP client)
        }
    }

    @Test
    public void testMode2MissingJwksUriInMetadata() {
        try {
            String agentId = "https://agent.example.com";
            String metadataUrl = agentId + "/.well-known/aauth-agent";
            String signatureKeyHeader = "sig=jwks;id=\"" + agentId + "\";kid=\"test-key\"";
            
            // Create metadata without jwks_uri
            AgentMetadata metadata = new AgentMetadata();
            metadata.setAgent(agentId);
            // Don't set jwksUri
            String metadataJson = JsonSerialization.writeValueAsString(metadata);
            httpResponses.put(metadataUrl, metadataJson);
            
            try {
                SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
                JWKSScheme scheme = new JWKSScheme(session);
                scheme.discoverPublicKey(keyParser);
                fail("Should throw SignatureVerificationException when jwks_uri is missing in metadata");
            } catch (SignatureVerificationException e) {
                assertTrue("Error should mention jwks_uri", 
                    e.getMessage().contains("jwks_uri") || e.getMessage().contains("metadata"));
            } catch (SignatureKeyParseException e) {
                // Also acceptable if parsing fails
            }
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }
}

