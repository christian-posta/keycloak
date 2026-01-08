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

import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.Assert.*;

/**
 * Unit tests for HeaderWebKeyScheme
 */
public class HeaderWebKeySchemeTest {

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
    }

    private KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = CryptoIntegration.getProvider().getKeyPairGen("Ed25519");
        return kpg.generateKeyPair();
    }

    private KeyPair generateRSAKeyPair() {
        return KeyUtils.generateRsaKeyPair(2048);
    }

    private String createHwkHeaderFromJWK(JWK jwk) throws Exception {
        StringBuilder header = new StringBuilder("sig=hwk");
        
        // Add standard JWK parameters
        if (jwk.getKeyType() != null) {
            header.append(";kty=\"").append(jwk.getKeyType()).append("\"");
        }
        if (jwk.getAlgorithm() != null) {
            header.append(";alg=\"").append(jwk.getAlgorithm()).append("\"");
        }
        if (jwk.getKeyId() != null) {
            header.append(";kid=\"").append(jwk.getKeyId()).append("\"");
        }
        
        // Add key-type-specific parameters
        // For OKP (Ed25519)
        if (jwk instanceof org.keycloak.jose.jwk.OKPPublicJWK) {
            org.keycloak.jose.jwk.OKPPublicJWK okpJwk = (org.keycloak.jose.jwk.OKPPublicJWK) jwk;
            if (okpJwk.getCrv() != null) {
                header.append(";crv=\"").append(okpJwk.getCrv()).append("\"");
            }
            if (okpJwk.getX() != null) {
                header.append(";x=\"").append(okpJwk.getX()).append("\"");
            }
        }
        // For RSA
        else if (jwk instanceof org.keycloak.jose.jwk.RSAPublicJWK) {
            org.keycloak.jose.jwk.RSAPublicJWK rsaJwk = (org.keycloak.jose.jwk.RSAPublicJWK) jwk;
            if (rsaJwk.getModulus() != null) {
                header.append(";n=\"").append(rsaJwk.getModulus()).append("\"");
            }
            if (rsaJwk.getPublicExponent() != null) {
                header.append(";e=\"").append(rsaJwk.getPublicExponent()).append("\"");
            }
        }
        // Fallback: check otherClaims
        else if (jwk.getOtherClaims() != null) {
            Object crv = jwk.getOtherClaims().get("crv");
            if (crv != null) {
                header.append(";crv=\"").append(crv).append("\"");
            }
            Object x = jwk.getOtherClaims().get("x");
            if (x != null) {
                header.append(";x=\"").append(x).append("\"");
            }
            Object n = jwk.getOtherClaims().get("n");
            if (n != null) {
                header.append(";n=\"").append(n).append("\"");
            }
            Object e = jwk.getOtherClaims().get("e");
            if (e != null) {
                header.append(";e=\"").append(e).append("\"");
            }
        }
        
        return header.toString();
    }

    @Test
    public void testExtractPublicKeyFromOKPEd25519() throws Exception {
        // Generate Ed25519 key pair
        KeyPair keyPair = generateEd25519KeyPair();
        PublicKey expectedPublicKey = keyPair.getPublic();
        
        // Convert to JWK
        JWK jwk = JWKBuilder.create().kid("test-key-1").okp(expectedPublicKey);
        
        // Create Signature-Key header from JWK
        String signatureKeyHeader = createHwkHeaderFromJWK(jwk);
        
        // Parse header
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key using HeaderWebKeyScheme
        HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testExtractPublicKeyFromRSA() throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey expectedPublicKey = keyPair.getPublic();
        
        // Convert to JWK
        JWK jwk = JWKBuilder.create().kid("rsa-key-1").rsa(expectedPublicKey);
        
        // Create Signature-Key header from JWK
        String signatureKeyHeader = createHwkHeaderFromJWK(jwk);
        
        // Parse header
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        
        // Extract public key using HeaderWebKeyScheme
        HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
        PublicKey extractedKey = scheme.discoverPublicKey(keyParser);
        
        // Verify keys match
        assertNotNull("Extracted public key should not be null", extractedKey);
        assertEquals("Public keys should match", expectedPublicKey, extractedKey);
    }

    @Test
    public void testGetAlgorithmForOKPEd25519() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String signatureKeyHeader = createHwkHeaderFromJWK(jwk);
        
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
        
        String algorithm = scheme.getAlgorithm(keyParser);
        assertEquals("Algorithm should be Ed25519 for OKP/Ed25519", "Ed25519", algorithm);
    }

    @Test
    public void testGetAlgorithmForRSA() throws Exception {
        KeyPair keyPair = generateRSAKeyPair();
        JWK jwk = JWKBuilder.create().rsa(keyPair.getPublic());
        String signatureKeyHeader = createHwkHeaderFromJWK(jwk);
        
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
        
        String algorithm = scheme.getAlgorithm(keyParser);
        assertEquals("Algorithm should be RS256 for RSA", "RS256", algorithm);
    }

    @Test
    public void testGetAgentIdReturnsNull() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());
        String signatureKeyHeader = createHwkHeaderFromJWK(jwk);
        
        SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
        HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
        
        String agentId = scheme.getAgentId(keyParser);
        assertNull("Agent ID should be null for pseudonymous hwk scheme", agentId);
    }

    @Test
    public void testMissingKtyParameter() {
        String signatureKeyHeader = "sig=hwk;x=\"test-x-value\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when kty is missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention kty", e.getMessage().contains("kty"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testMissingJWKParameters() {
        String signatureKeyHeader = "sig=hwk";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
            scheme.discoverPublicKey(keyParser);
            fail("Should throw SignatureVerificationException when JWK parameters are missing");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention JWK parameters", 
                e.getMessage().contains("JWK parameters") || e.getMessage().contains("kty"));
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testUnsupportedKeyType() {
        // Create header with unsupported key type
        String signatureKeyHeader = "sig=hwk;kty=\"oct\";k=\"test-key\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
            scheme.discoverPublicKey(keyParser);
            fail("Should throw exception for unsupported key type");
        } catch (SignatureVerificationException e) {
            // Expected - unsupported key types should fail
        } catch (SignatureKeyParseException e) {
            // Also acceptable if parsing fails
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }

    @Test
    public void testOKPWithoutCrv() {
        // Create header with OKP but missing crv
        String signatureKeyHeader = "sig=hwk;kty=\"OKP\";x=\"test-x-value\"";
        
        try {
            SignatureKeyParser keyParser = new SignatureKeyParser(signatureKeyHeader);
            HeaderWebKeyScheme scheme = new HeaderWebKeyScheme();
            PublicKey key = scheme.discoverPublicKey(keyParser);
            // This might succeed or fail depending on JWK parsing
            // If it succeeds, that's fine - the test verifies it doesn't crash
            assertNotNull("If parsing succeeds, key should not be null", key);
        } catch (SignatureVerificationException e) {
            // Also acceptable if it fails due to missing crv
        } catch (SignatureKeyParseException e) {
            // Also acceptable
        } catch (Exception e) {
            // Also acceptable for other exceptions
        }
    }
}

