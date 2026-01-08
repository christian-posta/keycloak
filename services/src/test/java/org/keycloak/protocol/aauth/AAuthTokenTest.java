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

package org.keycloak.protocol.aauth;

import org.junit.Test;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.representations.AAuthToken;
import org.keycloak.util.JsonSerialization;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for AAuthToken representation
 */
public class AAuthTokenTest {

    @Test
    public void testTokenCreation() {
        AAuthToken token = new AAuthToken();
        token.issuer("https://auth.example.com");
        token.audience("https://resource.example.com");
        token.agent("https://agent.example.com");
        token.exp(Time.currentTime() + 3600L);
        token.issuedNow();

        assertEquals("https://auth.example.com", token.getIssuer());
        assertEquals("https://resource.example.com", token.getAudience()[0]);
        assertEquals("https://agent.example.com", token.getAgent());
        assertNotNull(token.getExp());
        assertNotNull(token.getIat());
    }

    @Test
    public void testAgentDelegate() {
        AAuthToken token = new AAuthToken();
        token.agentDelegate("https://delegate.example.com");

        assertEquals("https://delegate.example.com", token.getAgentDelegate());
    }

    @Test
    public void testScope() {
        AAuthToken token = new AAuthToken();
        token.setScope("data.read data.write");

        assertEquals("data.read data.write", token.getScope());
    }

    @Test
    public void testCnfJwk() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());

        AAuthToken token = new AAuthToken();
        token.setCnfJwk(jwk);

        assertNotNull(token.getCnf());
        assertNotNull(token.getCnf().getJwk());
        assertEquals(jwk, token.getCnf().getJwk());
    }

    @Test
    public void testActClaim() {
        AAuthToken token = new AAuthToken();
        Map<String, Object> act = new HashMap<>();
        act.put("sub", "user123");
        act.put("iss", "https://auth.example.com");
        token.setAct(act);

        assertNotNull(token.getAct());
        assertEquals("user123", token.getAct().get("sub"));
    }

    @Test
    public void testTokenSerialization() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        JWK jwk = JWKBuilder.create().okp(keyPair.getPublic());

        AAuthToken token = new AAuthToken();
        token.issuer("https://auth.example.com");
        token.audience("https://resource.example.com");
        token.agent("https://agent.example.com");
        token.setScope("data.read");
        token.setCnfJwk(jwk);
        token.exp(Time.currentTime() + 3600L);
        token.issuedNow();

        // Serialize to JSON
        String json = JsonSerialization.writeValueAsString(token);
        assertNotNull(json);
        assertTrue(json.contains("\"iss\":\"https://auth.example.com\""));
        assertTrue(json.contains("\"agent\":\"https://agent.example.com\""));
        assertTrue(json.contains("\"scope\":\"data.read\""));
        assertTrue(json.contains("\"cnf\""));

        // Deserialize back
        AAuthToken deserialized = JsonSerialization.readValue(json, AAuthToken.class);
        assertEquals(token.getIssuer(), deserialized.getIssuer());
        assertEquals(token.getAgent(), deserialized.getAgent());
        assertEquals(token.getScope(), deserialized.getScope());
        assertNotNull(deserialized.getCnf());
        assertNotNull(deserialized.getCnf().getJwk());
    }

    @Test
    public void testTokenWithoutAgentClaim() {
        AAuthToken token = new AAuthToken();
        token.issuer("https://auth.example.com");
        // When agent == aud, agent claim should not be set
        token.audience("https://agent.example.com");

        assertNull(token.getAgent()); // Agent claim not set when agent == aud
    }

    private KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }
}

