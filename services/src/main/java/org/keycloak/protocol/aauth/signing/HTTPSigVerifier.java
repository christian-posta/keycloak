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

import org.jboss.logging.Logger;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureBaseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.protocol.aauth.signing.schemes.SignatureScheme;
import org.keycloak.protocol.aauth.signing.schemes.SignatureSchemeFactory;

import java.security.PublicKey;
import java.util.Base64;

/**
 * Main HTTP Message Signature verifier per RFC 9421 and AAuth profile.
 * 
 * Verifies HTTP Message Signatures by:
 * 1. Parsing Signature-Key header to determine scheme
 * 2. Discovering public key based on scheme
 * 3. Building signature base string
 * 4. Verifying signature using discovered key
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9421">RFC 9421: HTTP Message Signatures</a>
 */
public class HTTPSigVerifier {

    private static final Logger logger = Logger.getLogger(HTTPSigVerifier.class);

    private final KeycloakSession session;

    public HTTPSigVerifier(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Verify an HTTP Message Signature.
     * 
     * @param request The HTTP request containing signature headers
     * @return Verification result containing agent identity and public key
     * @throws SignatureVerificationException If verification fails
     */
    public VerificationResult verify(HttpRequest request) throws SignatureVerificationException {
        // 1. Extract and parse Signature-Key header
        String signatureKeyHeader = request.getHttpHeaders().getHeaderString("Signature-Key");
        if (signatureKeyHeader == null) {
            throw new SignatureVerificationException("Missing Signature-Key header");
        }

        SignatureKeyParser keyParser;
        try {
            keyParser = new SignatureKeyParser(signatureKeyHeader);
        } catch (SignatureKeyParseException e) {
            throw new SignatureVerificationException("Failed to parse Signature-Key header", e);
        }

        // 2. Extract Signature-Input header
        String signatureInputHeader = request.getHttpHeaders().getHeaderString("Signature-Input");
        if (signatureInputHeader == null) {
            throw new SignatureVerificationException("Missing Signature-Input header");
        }

        // 3. Extract Signature header
        String signatureHeader = request.getHttpHeaders().getHeaderString("Signature");
        if (signatureHeader == null) {
            throw new SignatureVerificationException("Missing Signature header");
        }

        // 4. Verify label consistency (AAuth profile requirement)
        String signatureLabel = extractSignatureLabel(signatureHeader);
        if (!signatureLabel.equals(keyParser.getSignatureLabel())) {
            throw new SignatureVerificationException(
                "Signature label mismatch: Signature-Key has '" + keyParser.getSignatureLabel() + 
                "' but Signature has '" + signatureLabel + "'");
        }

        // 5. Discover public key based on scheme
        SignatureScheme scheme = SignatureSchemeFactory.create(session, keyParser);
        PublicKey publicKey;
        try {
            publicKey = scheme.discoverPublicKey(keyParser);
        } catch (Exception e) {
            throw new SignatureVerificationException("Failed to discover public key for scheme: " + keyParser.getScheme(), e);
        }

        // 6. Build signature base string
        byte[] signatureBase;
        try {
            signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInputHeader, signatureLabel);
        } catch (SignatureBaseException e) {
            throw new SignatureVerificationException("Failed to build signature base", e);
        }

        // 7. Extract signature bytes from Signature header
        byte[] signatureBytes = extractSignatureBytes(signatureHeader, signatureLabel);

        // 8. Verify signature
        String algorithm = scheme.getAlgorithm(keyParser);
        boolean valid = verifySignature(signatureBase, signatureBytes, publicKey, algorithm);
        
        if (!valid) {
            throw new SignatureVerificationException("Signature verification failed");
        }

        // 9. Extract agent identity from scheme
        String agentId = scheme.getAgentId(keyParser);

        logger.debugf("HTTP Message Signature verified successfully for agent: %s", agentId);

        return new VerificationResult(agentId, publicKey, keyParser.getScheme());
    }

    /**
     * Extract the signature label from the Signature header.
     * Format: label=:base64signature:
     */
    private String extractSignatureLabel(String signatureHeader) throws SignatureVerificationException {
        int equalsIndex = signatureHeader.indexOf('=');
        if (equalsIndex <= 0) {
            throw new SignatureVerificationException("Invalid Signature header format");
        }
        return signatureHeader.substring(0, equalsIndex).trim();
    }

    /**
     * Extract signature bytes from the Signature header.
     * Format: label=:base64signature:
     */
    private byte[] extractSignatureBytes(String signatureHeader, String signatureLabel) throws SignatureVerificationException {
        String labelPrefix = signatureLabel + "=:";
        int startIndex = signatureHeader.indexOf(labelPrefix);
        if (startIndex < 0) {
            throw new SignatureVerificationException("Signature label '" + signatureLabel + "' not found in Signature header");
        }

        int valueStart = startIndex + labelPrefix.length();
        int valueEnd = signatureHeader.indexOf(':', valueStart);
        if (valueEnd < 0) {
            // No trailing colon, signature extends to end
            valueEnd = signatureHeader.length();
        }

        String base64Signature = signatureHeader.substring(valueStart, valueEnd);
        try {
            return Base64.getUrlDecoder().decode(base64Signature);
        } catch (IllegalArgumentException e) {
            throw new SignatureVerificationException("Invalid base64 signature", e);
        }
    }

    /**
     * Verify the signature using the public key and algorithm.
     */
    private boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) 
            throws SignatureVerificationException {
        
        try {
            // Create KeyWrapper from PublicKey
            org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
            keyWrapper.setPublicKey(publicKey);
            
            // Map HTTPSig algorithm names to Keycloak algorithm names
            // Ed25519 in HTTPSig maps to EdDSA in Keycloak
            String keycloakAlgorithm = algorithm;
            if ("Ed25519".equals(algorithm)) {
                keycloakAlgorithm = org.keycloak.crypto.Algorithm.EdDSA;
                keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
            } else if ("Ed448".equals(algorithm)) {
                keycloakAlgorithm = org.keycloak.crypto.Algorithm.EdDSA;
                keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed448);
            }
            keyWrapper.setAlgorithm(keycloakAlgorithm);
            
            // Use Keycloak's signature verification infrastructure
            org.keycloak.crypto.SignatureVerifierContext verifierContext = 
                new org.keycloak.crypto.AsymmetricSignatureVerifierContext(keyWrapper);

            return verifierContext.verify(data, signature);
            
        } catch (org.keycloak.common.VerificationException e) {
            logger.debugf(e, "Signature verification failed");
            throw new SignatureVerificationException("Signature verification failed", e);
        } catch (Exception e) {
            logger.debugf(e, "Unexpected error during signature verification");
            throw new SignatureVerificationException("Signature verification failed", e);
        }
    }

    /**
     * Result of signature verification.
     */
    public static class VerificationResult {
        private final String agentId;
        private final PublicKey publicKey;
        private final String scheme;

        public VerificationResult(String agentId, PublicKey publicKey, String scheme) {
            this.agentId = agentId;
            this.publicKey = publicKey;
            this.scheme = scheme;
        }

        public String getAgentId() {
            return agentId;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public String getScheme() {
            return scheme;
        }
    }
}

