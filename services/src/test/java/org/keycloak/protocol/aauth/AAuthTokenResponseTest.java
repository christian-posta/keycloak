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
import org.keycloak.representations.AAuthTokenResponse;
import org.keycloak.util.JsonSerialization;

import static org.junit.Assert.*;

/**
 * Unit tests for AAuthTokenResponse
 */
public class AAuthTokenResponseTest {

    @Test
    public void testResponseCreation() {
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setAuthToken("eyJhbGciOiJFZERTQSJ9...");
        response.setExpiresIn(3600L);
        response.setTokenType("AAuth");

        assertEquals("eyJhbGciOiJFZERTQSJ9...", response.getAuthToken());
        assertEquals(3600L, response.getExpiresIn());
        assertEquals("AAuth", response.getTokenType());
    }

    @Test
    public void testResponseWithRefreshToken() {
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setAuthToken("token123");
        response.setRefreshToken("refresh123");
        response.setExpiresIn(3600L);

        assertEquals("token123", response.getAuthToken());
        assertEquals("refresh123", response.getRefreshToken());
    }

    @Test
    public void testResponseWithRequestToken() {
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setAuthToken("token123");
        response.setRequestToken("request123");
        response.setExpiresIn(3600L);

        assertEquals("token123", response.getAuthToken());
        assertEquals("request123", response.getRequestToken());
    }

    @Test
    public void testErrorResponse() {
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setError("invalid_request");
        response.setErrorDescription("Missing required parameter");
        response.setErrorUri("https://example.com/errors/invalid_request");

        assertEquals("invalid_request", response.getError());
        assertEquals("Missing required parameter", response.getErrorDescription());
        assertEquals("https://example.com/errors/invalid_request", response.getErrorUri());
    }

    @Test
    public void testResponseSerialization() throws Exception {
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setAuthToken("eyJhbGciOiJFZERTQSJ9...");
        response.setExpiresIn(3600L);
        response.setTokenType("AAuth");

        String json = JsonSerialization.writeValueAsString(response);
        assertNotNull(json);
        assertTrue(json.contains("\"auth_token\""));
        assertTrue(json.contains("\"expires_in\":3600"));
        assertTrue(json.contains("\"token_type\":\"AAuth\""));

        // Deserialize back
        AAuthTokenResponse deserialized = JsonSerialization.readValue(json, AAuthTokenResponse.class);
        assertEquals(response.getAuthToken(), deserialized.getAuthToken());
        assertEquals(response.getExpiresIn(), deserialized.getExpiresIn());
        assertEquals(response.getTokenType(), deserialized.getTokenType());
    }
}

