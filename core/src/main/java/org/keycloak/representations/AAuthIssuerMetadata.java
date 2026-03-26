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

package org.keycloak.representations;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * AAuth Issuer Metadata as defined in the updated AAuth specification.
 *
 * Published at {@code /.well-known/aauth-issuer.json}.
 */
public class AAuthIssuerMetadata {

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("interaction_endpoint")
    private String interactionEndpoint;

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public String getTokenEndpoint() { return tokenEndpoint; }
    public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }

    public String getInteractionEndpoint() { return interactionEndpoint; }
    public void setInteractionEndpoint(String interactionEndpoint) { this.interactionEndpoint = interactionEndpoint; }
}
