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

package org.keycloak.protocol.aauth.wellknown;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AAuthIssuerMetadata;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import java.net.URI;

/**
 * Well-known provider for AAuth Issuer Metadata.
 *
 * Implements {@code /.well-known/aauth-issuer.json} per updated AAuth specification.
 *
 * Metadata shape:
 * <pre>
 * {
 *   "issuer": "https://auth.example/realms/myrealm",
 *   "token_endpoint": "https://auth.example/realms/myrealm/protocol/aauth/token",
 *   "interaction_endpoint": "https://auth.example/realms/myrealm/protocol/aauth/interact",
 *   "jwks_uri": "https://auth.example/realms/myrealm/protocol/aauth/certs"
 * }
 * </pre>
 */
public class AAuthIssuerWellKnownProvider implements WellKnownProvider {

    private final KeycloakSession session;

    public AAuthIssuerWellKnownProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getConfig() {
        UriInfo frontendUriInfo = session.getContext().getUri(UrlType.FRONTEND);
        UriInfo backendUriInfo = session.getContext().getUri(UrlType.BACKEND);

        RealmModel realm = session.getContext().getRealm();

        UriBuilder frontendUriBuilder = RealmsResource.protocolUrl(frontendUriInfo);
        UriBuilder backendUriBuilder = RealmsResource.protocolUrl(backendUriInfo);

        AAuthIssuerMetadata metadata = new AAuthIssuerMetadata();

        metadata.setIssuer(Urls.realmIssuer(frontendUriInfo.getBaseUri(), realm.getName()));

        // jwks_uri — backend URL for JWKS
        URI jwksUri = backendUriBuilder.clone()
                .path("/certs")
                .build(realm.getName(), "aauth");
        metadata.setJwksUri(jwksUri.toString());

        // token_endpoint — backend URL (agents call this)
        URI tokenEndpoint = backendUriBuilder.clone()
                .path("/token")
                .build(realm.getName(), "aauth");
        metadata.setTokenEndpoint(tokenEndpoint.toString());

        // interaction_endpoint — frontend URL (browser interaction)
        URI interactionEndpoint = frontendUriBuilder.clone()
                .path("/interact")
                .build(realm.getName(), "aauth");
        metadata.setInteractionEndpoint(interactionEndpoint.toString());

        return metadata;
    }

    @Override
    public void close() {}
}
