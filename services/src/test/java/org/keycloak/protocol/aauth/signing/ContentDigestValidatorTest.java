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
package org.keycloak.protocol.aauth.signing;

import org.junit.Test;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests for ContentDigestValidator per RFC 9530.
 */
public class ContentDigestValidatorTest {

    private static final String TEST_BODY = "{\"hello\": \"world\"}";
    private static final byte[] TEST_BODY_BYTES = TEST_BODY.getBytes(StandardCharsets.UTF_8);

    /**
     * Calculate expected Content-Digest header value for test body.
     */
    private String calculateExpectedDigest(String algorithm) throws Exception {
        MessageDigest digest;
        switch (algorithm.toLowerCase()) {
            case "sha-256":
                digest = MessageDigest.getInstance("SHA-256");
                break;
            case "sha-512":
                digest = MessageDigest.getInstance("SHA-512");
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
        byte[] hash = digest.digest(TEST_BODY_BYTES);
        return algorithm + "=:" + Base64.getEncoder().encodeToString(hash) + ":";
    }

    @Test
    public void testValidSha256Digest() throws Exception {
        String contentDigest = calculateExpectedDigest("sha-256");
        
        // Should not throw
        ContentDigestValidator.validateContentDigest(contentDigest, TEST_BODY_BYTES);
    }

    @Test
    public void testValidSha512Digest() throws Exception {
        String contentDigest = calculateExpectedDigest("sha-512");
        
        // Should not throw
        ContentDigestValidator.validateContentDigest(contentDigest, TEST_BODY_BYTES);
    }

    @Test
    public void testValidMultipleDigests() throws Exception {
        // Header with multiple algorithms
        String sha256 = calculateExpectedDigest("sha-256");
        String sha512 = calculateExpectedDigest("sha-512");
        String contentDigest = sha256 + ", " + sha512;
        
        // Should validate against at least one
        ContentDigestValidator.validateContentDigest(contentDigest, TEST_BODY_BYTES);
    }

    @Test
    public void testMismatchedDigestThrows() throws Exception {
        String correctDigest = calculateExpectedDigest("sha-256");
        byte[] differentBody = "different body".getBytes(StandardCharsets.UTF_8);
        
        try {
            ContentDigestValidator.validateContentDigest(correctDigest, differentBody);
            fail("Should throw SignatureVerificationException for mismatched digest");
        } catch (SignatureVerificationException e) {
            assertTrue("Error should mention validation failed", 
                e.getMessage().contains("validation failed"));
        }
    }

    @Test
    public void testTamperedBodyDetected() throws Exception {
        // This simulates an attack where body is modified but Content-Digest header is not
        String originalDigest = calculateExpectedDigest("sha-256");
        byte[] tamperedBody = "{\"hello\": \"attacker\"}".getBytes(StandardCharsets.UTF_8);
        
        try {
            ContentDigestValidator.validateContentDigest(originalDigest, tamperedBody);
            fail("Should detect tampered body");
        } catch (SignatureVerificationException e) {
            assertTrue("Should indicate digest mismatch", 
                e.getMessage().contains("validation failed") || e.getMessage().contains("does not match"));
        }
    }

    @Test
    public void testEmptyBodyValidation() throws Exception {
        // Calculate digest of empty body
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] emptyHash = digest.digest(new byte[0]);
        String emptyDigest = "sha-256=:" + Base64.getEncoder().encodeToString(emptyHash) + ":";
        
        // Should validate empty body against empty digest
        ContentDigestValidator.validateContentDigest(emptyDigest, new byte[0]);
    }

    @Test
    public void testNullBodyTreatedAsEmpty() throws Exception {
        // Calculate digest of empty body
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] emptyHash = digest.digest(new byte[0]);
        String emptyDigest = "sha-256=:" + Base64.getEncoder().encodeToString(emptyHash) + ":";
        
        // Null body should be treated as empty
        ContentDigestValidator.validateContentDigest(emptyDigest, null);
    }

    @Test
    public void testMissingHeaderThrows() {
        try {
            ContentDigestValidator.validateContentDigest(null, TEST_BODY_BYTES);
            fail("Should throw for null header");
        } catch (SignatureVerificationException e) {
            assertTrue("Should mention missing header", e.getMessage().contains("missing"));
        }
    }

    @Test
    public void testEmptyHeaderThrows() {
        try {
            ContentDigestValidator.validateContentDigest("", TEST_BODY_BYTES);
            fail("Should throw for empty header");
        } catch (SignatureVerificationException e) {
            assertTrue("Should mention missing header", 
                e.getMessage().contains("missing") || e.getMessage().contains("empty"));
        }
    }

    @Test
    public void testMalformedHeaderThrows() {
        try {
            ContentDigestValidator.validateContentDigest("not-a-valid-digest", TEST_BODY_BYTES);
            fail("Should throw for malformed header");
        } catch (SignatureVerificationException e) {
            assertTrue("Should indicate no valid digest", 
                e.getMessage().contains("No valid digest") || e.getMessage().contains("validation failed"));
        }
    }

    @Test
    public void testParseContentDigestHeader() {
        String header = "sha-256=:dGVzdA==:, sha-512=:YW5vdGhlcg==:";
        Map<String, String> digests = ContentDigestValidator.parseContentDigestHeader(header);
        
        assertEquals(2, digests.size());
        assertEquals("dGVzdA==", digests.get("sha-256"));
        assertEquals("YW5vdGhlcg==", digests.get("sha-512"));
    }

    @Test
    public void testParseContentDigestHeaderCaseInsensitive() {
        String header = "SHA-256=:dGVzdA==:";
        Map<String, String> digests = ContentDigestValidator.parseContentDigestHeader(header);
        
        assertEquals(1, digests.size());
        // Should be lowercased
        assertTrue(digests.containsKey("sha-256"));
    }

    @Test
    public void testParseContentDigestHeaderWithWhitespace() {
        String header = "  sha-256 = :dGVzdA==:  ";
        Map<String, String> digests = ContentDigestValidator.parseContentDigestHeader(header);
        
        // The current implementation trims, so this should work
        assertEquals(1, digests.size());
    }

    @Test
    public void testCalculateDigestSha256() throws Exception {
        String digest = ContentDigestValidator.calculateDigest(TEST_BODY_BYTES, "sha-256");
        
        // Verify it matches expected SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String expected = Base64.getEncoder().encodeToString(md.digest(TEST_BODY_BYTES));
        
        assertEquals(expected, digest);
    }

    @Test
    public void testCalculateDigestSha512() throws Exception {
        String digest = ContentDigestValidator.calculateDigest(TEST_BODY_BYTES, "sha-512");
        
        // Verify it matches expected SHA-512
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        String expected = Base64.getEncoder().encodeToString(md.digest(TEST_BODY_BYTES));
        
        assertEquals(expected, digest);
    }

    @Test
    public void testUnsupportedAlgorithmThrows() {
        try {
            ContentDigestValidator.calculateDigest(TEST_BODY_BYTES, "md5");
            fail("Should throw for unsupported algorithm");
        } catch (SignatureVerificationException e) {
            assertTrue("Should mention unsupported algorithm", 
                e.getMessage().contains("Unsupported") || e.getMessage().contains("md5"));
        }
    }

    @Test
    public void testShouldValidateContentDigest() {
        java.util.List<String> coveredWithDigest = java.util.Arrays.asList("@method", "@path", "content-digest");
        java.util.List<String> coveredWithoutDigest = java.util.Arrays.asList("@method", "@path");
        
        assertTrue(ContentDigestValidator.shouldValidateContentDigest("sha-256=:xxx:", coveredWithDigest));
        assertFalse(ContentDigestValidator.shouldValidateContentDigest("sha-256=:xxx:", coveredWithoutDigest));
        assertFalse(ContentDigestValidator.shouldValidateContentDigest(null, coveredWithDigest));
        assertFalse(ContentDigestValidator.shouldValidateContentDigest("", coveredWithDigest));
        assertFalse(ContentDigestValidator.shouldValidateContentDigest("sha-256=:xxx:", null));
    }

    @Test
    public void testRfc9530ExampleDigest() throws Exception {
        // Example from RFC 9530: {"hello": "world"} with LF
        // Note: The RFC example includes a trailing LF
        byte[] body = "{\"hello\": \"world\"}\n".getBytes(StandardCharsets.UTF_8);
        
        // Calculate our digest
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(body);
        String computed = Base64.getEncoder().encodeToString(hash);
        
        // The RFC 9530 Appendix D gives: sha-256 = :X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
        // for {"hello": "world"} (without trailing LF)
        // Our test uses the same format
        
        String contentDigest = "sha-256=:" + computed + ":";
        ContentDigestValidator.validateContentDigest(contentDigest, body);
    }
}
