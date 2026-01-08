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

import org.junit.Test;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

/**
 * Unit tests for SignatureKeyParser
 */
public class SignatureKeyParserTest {

    @Test
    public void testParseHwkScheme() throws SignatureKeyParseException {
        String header = "sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"test-x-value\";kid=\"test-key-1\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("hwk", parser.getScheme());
        assertEquals("OKP", parser.getParameter("kty"));
        assertEquals("Ed25519", parser.getParameter("crv"));
        assertEquals("test-x-value", parser.getParameter("x"));
        assertEquals("test-key-1", parser.getKid());
    }

    @Test
    public void testParseHwkSchemeUnquoted() throws SignatureKeyParseException {
        String header = "sig=hwk;kty=OKP;crv=Ed25519;x=test-x-value;kid=test-key-1";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("hwk", parser.getScheme());
        assertEquals("OKP", parser.getParameter("kty"));
        assertEquals("Ed25519", parser.getParameter("crv"));
        assertEquals("test-x-value", parser.getParameter("x"));
        assertEquals("test-key-1", parser.getKid());
    }

    @Test
    public void testParseHwkSchemeRSA() throws SignatureKeyParseException {
        String header = "sig=hwk;kty=\"RSA\";n=\"modulus-value\";e=\"AQAB\";kid=\"rsa-key-1\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("hwk", parser.getScheme());
        assertEquals("RSA", parser.getParameter("kty"));
        assertEquals("modulus-value", parser.getParameter("n"));
        assertEquals("AQAB", parser.getParameter("e"));
        assertEquals("rsa-key-1", parser.getKid());
    }

    @Test
    public void testParseJwksSchemeMode2() throws SignatureKeyParseException {
        // Mode 2: Identifier + Metadata
        String header = "sig=jwks;id=\"https://agent.example.com\";kid=\"key-1\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("jwks", parser.getScheme());
        assertEquals("https://agent.example.com", parser.getAgentId());
        assertEquals("key-1", parser.getKid());
    }

    @Test
    public void testParseJwksSchemeMode1() throws SignatureKeyParseException {
        // Mode 1: Direct JWKS URL
        String header = "sig=jwks;jwks=\"https://agent.example.com/jwks.json\";kid=\"key-1\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("jwks", parser.getScheme());
        assertEquals("https://agent.example.com/jwks.json", parser.getParameter("jwks"));
        assertEquals("key-1", parser.getKid());
        // Mode 1 should not have 'id' parameter
        assertNull(parser.getAgentId());
    }

    @Test
    public void testParseJwksSchemeMode2WithWellKnown() throws SignatureKeyParseException {
        // Mode 2: Identifier + Metadata with custom well-known document
        String header = "sig=jwks;id=\"https://agent.example.com\";kid=\"key-1\";well-known=\"aauth-agent\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("jwks", parser.getScheme());
        assertEquals("https://agent.example.com", parser.getAgentId());
        assertEquals("key-1", parser.getKid());
        assertEquals("aauth-agent", parser.getWellKnown());
    }

    @Test
    public void testParseX509Scheme() throws SignatureKeyParseException {
        String header = "sig=x509;x5u=\"https://agent.example.com/certs.pem\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("x509", parser.getScheme());
        assertEquals("https://agent.example.com/certs.pem", parser.getX5u());
    }

    @Test
    public void testParseJwtScheme() throws SignatureKeyParseException {
        String header = "sig=jwt;jwt=\"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("jwt", parser.getScheme());
        assertEquals("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature", parser.getJWT());
    }

    @Test
    public void testParseSchemeOnly() throws SignatureKeyParseException {
        String header = "sig=hwk";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("sig", parser.getSignatureLabel());
        assertEquals("hwk", parser.getScheme());
        assertNull(parser.getParameter("kty"));
    }

    @Test
    public void testParseMixedQuotedUnquoted() throws SignatureKeyParseException {
        String header = "sig=hwk;kty=\"OKP\";crv=Ed25519;x=\"test-x\";kid=test-key";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("OKP", parser.getParameter("kty"));
        assertEquals("Ed25519", parser.getParameter("crv"));
        assertEquals("test-x", parser.getParameter("x"));
        assertEquals("test-key", parser.getKid());
    }

    @Test
    public void testParseEmptyHeader() {
        try {
            new SignatureKeyParser("");
            fail("Should throw SignatureKeyParseException for empty header");
        } catch (SignatureKeyParseException e) {
            // Expected
        }
    }

    @Test
    public void testParseNullHeader() {
        try {
            new SignatureKeyParser(null);
            fail("Should throw SignatureKeyParseException for null header");
        } catch (SignatureKeyParseException e) {
            // Expected
        }
    }

    @Test
    public void testGetParameter() throws SignatureKeyParseException {
        String header = "sig=hwk;kty=\"OKP\";custom=\"value\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        assertEquals("value", parser.getParameter("custom"));
        assertNull(parser.getParameter("nonexistent"));
    }

    @Test
    public void testGetParameterCaseSensitive() throws SignatureKeyParseException {
        String header = "sig=hwk;KTY=\"OKP\";kty=\"EC\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        // Parameters are case-sensitive
        assertEquals("OKP", parser.getParameter("KTY"));
        assertEquals("EC", parser.getParameter("kty"));
    }

    @Test
    public void testGetJWKParameters() throws SignatureKeyParseException {
        String header = "sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"test-x\";kid=\"test-key\";alg=\"EdDSA\"";
        SignatureKeyParser parser = new SignatureKeyParser(header);
        
        Map<String, String> jwkParams = parser.getJWKParameters();
        assertEquals("OKP", jwkParams.get("kty"));
        assertEquals("Ed25519", jwkParams.get("crv"));
        assertEquals("test-x", jwkParams.get("x"));
        assertEquals("test-key", jwkParams.get("kid"));
        // alg is a standard JWK parameter, so it should be included
        assertEquals("EdDSA", jwkParams.get("alg"));
    }
}

