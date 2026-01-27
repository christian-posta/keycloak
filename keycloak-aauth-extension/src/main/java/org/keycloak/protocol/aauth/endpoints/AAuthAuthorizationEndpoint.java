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

package org.keycloak.protocol.aauth.endpoints;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.models.utils.SystemClientUtil;
import org.keycloak.protocol.aauth.storage.AAuthAuthorizationCode;
import org.keycloak.protocol.aauth.storage.AAuthRequestToken;
import org.keycloak.protocol.aauth.storage.AAuthRequestTokenStore;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationSessionManager;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

/**
 * Authorization endpoint for AAuth user consent flow.
 * 
 * Handles user authentication and consent for AAuth authorization requests.
 * Similar to OIDC AuthorizationEndpoint but for AAuth protocol.
 */
public class AAuthAuthorizationEndpoint {

    private static final Logger logger = Logger.getLogger(AAuthAuthorizationEndpoint.class);
    
    private static final String REQUEST_TOKEN_PARAM = "request_token";
    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String STATE_PARAM = "state";
    private static final String CODE_PARAM = "code";
    private static final String ERROR_PARAM = "error";
    private static final String ERROR_DESCRIPTION_PARAM = "error_description";

    private final KeycloakSession session;
    private final EventBuilder event;
    private final RealmModel realm;
    private final ClientConnection clientConnection;

    public AAuthAuthorizationEndpoint(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.event = event;
        this.realm = session.getContext().getRealm();
        this.clientConnection = session.getContext().getConnection();
    }

    @GET
    public Response authorizeGet() {
        MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();
        return processAuthorization(params);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response authorizePost() {
        MultivaluedMap<String, String> params = session.getContext().getHttpRequest().getDecodedFormParameters();
        return processAuthorization(params);
    }


    private Response processAuthorization(MultivaluedMap<String, String> params) {
        event.event(EventType.LOGIN);
        
        checkSsl();
        checkRealm();
        
        String requestToken = params.getFirst(REQUEST_TOKEN_PARAM);
        String redirectUri = params.getFirst(REDIRECT_URI_PARAM);
        String state = params.getFirst(STATE_PARAM);
        
        // If request_token not in params, try to get it from authentication session (return from login)
        if (requestToken == null || requestToken.isEmpty()) {
            AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.getCurrentRootAuthenticationSession(realm);
            if (rootAuthSession != null) {
                ClientModel client = SystemClientUtil.getSystemClient(realm);
                // Get authentication session for the client (there should be only one)
                Map<String, AuthenticationSessionModel> authSessions = rootAuthSession.getAuthenticationSessions();
                for (AuthenticationSessionModel authSession : authSessions.values()) {
                    if (client.equals(authSession.getClient())) {
                        requestToken = authSession.getClientNote(REQUEST_TOKEN_PARAM);
                        if (redirectUri == null) {
                            redirectUri = authSession.getClientNote(REDIRECT_URI_PARAM);
                        }
                        if (state == null) {
                            state = authSession.getClientNote(STATE_PARAM);
                        }
                        break;
                    }
                }
            }
        }
        
        if (requestToken == null || requestToken.isEmpty()) {
            return createErrorResponse(redirectUri, OAuthErrorException.INVALID_REQUEST, 
                    "Missing required parameter: request_token");
        }

        // Validate request token
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        AAuthRequestToken tokenData = tokenStore.validateRequestToken(requestToken);
        
        if (tokenData == null) {
            return createErrorResponse(redirectUri, OAuthErrorException.INVALID_REQUEST, 
                    "Invalid or expired request_token");
        }

        // Use redirect_uri from token if not provided in request
        if (redirectUri == null || redirectUri.isEmpty()) {
            redirectUri = tokenData.getRedirectUri();
        } else if (!redirectUri.equals(tokenData.getRedirectUri())) {
            return createErrorResponse(tokenData.getRedirectUri(), OAuthErrorException.INVALID_REQUEST,
                    "redirect_uri mismatch");
        }

        // Check if user is authenticated
        UserSessionModel userSession = session.getContext().getUserSession();
        UserModel user = session.getContext().getUser();
        
        if (userSession == null || user == null) {
            // User not authenticated - redirect to login
            return redirectToLogin(requestToken, redirectUri, state);
        }

        // User is authenticated - show consent screen
        return showConsentScreen(tokenData, user);
    }

    private Response redirectToLogin(String requestToken, String redirectUri, String state) {
        // Create authentication session for login flow
        // Use system client since AAuth doesn't use traditional OIDC clients
        ClientModel client = SystemClientUtil.getSystemClient(realm);
        
        // Create root authentication session with browser cookie
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, true);
        
        // Create authentication session for the client
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        // Use "aauth" protocol so our AAuthLoginProtocol handles the post-authentication redirect
        authSession.setProtocol("aauth");
        
        // Store request token and redirect URI in authentication session
        URI currentUri = session.getContext().getUri().getRequestUri();
        authSession.setRedirectUri(currentUri.toString());
        authSession.setClientNote(REQUEST_TOKEN_PARAM, requestToken);
        if (redirectUri != null) {
            authSession.setClientNote(REDIRECT_URI_PARAM, redirectUri);
        }
        if (state != null) {
            authSession.setClientNote(STATE_PARAM, state);
        }
        
        // Build login URL - Keycloak will automatically use the authentication session cookie
        URI loginUrl = Urls.realmLoginPage(session.getContext().getUri().getBaseUri(), realm.getName());
        
        // Add tab_id parameter to link to the authentication session
        UriBuilder loginUriBuilder = UriBuilder.fromUri(loginUrl);
        loginUriBuilder.queryParam("client_id", client.getClientId());
        loginUriBuilder.queryParam("tab_id", authSession.getTabId());
        
        return Response.seeOther(loginUriBuilder.build()).build();
    }

    private Response showConsentScreen(AAuthRequestToken tokenData, UserModel user) {
        // For Phase 3, we'll auto-grant consent after authentication
        // In future phases, we can add a proper consent screen
        
        // Generate authorization code directly
        UserSessionModel userSession = session.getContext().getUserSession();
        if (userSession == null) {
            // Reconstruct request token string for redirect
            String requestTokenStr = tokenData.getId() + "." + Time.currentTime() + ".dummy";
            return redirectToLogin(requestTokenStr, tokenData.getRedirectUri(), tokenData.getState());
        }
        
        String code = generateAuthorizationCode(tokenData, userSession);
        
        // Note: Request token will be consumed during code exchange to prevent reuse
        
        event.event(EventType.CODE_TO_TOKEN);
        event.detail(Details.CODE_ID, code);
        event.success();
        
        return redirectWithCode(tokenData.getRedirectUri(), code, tokenData.getState());
    }

    private String generateAuthorizationCode(AAuthRequestToken tokenData, UserSessionModel userSession) {
        String codeId = UUID.randomUUID().toString();
        int codeLifespan = 60; // 60 seconds default
        
        // Create AAuth authorization code with request token data
        AAuthAuthorizationCode codeData = new AAuthAuthorizationCode(
                codeId,
                Time.currentTime() + codeLifespan,
                tokenData.getScope(),
                tokenData.getRedirectUri(),
                userSession.getId(),
                tokenData.getId(), // request token ID
                tokenData.getAgentId(),
                tokenData.getAgentJkt(),
                tokenData.getSignatureScheme(),
                tokenData.getResourceId()
        );
        
        // Store code in SingleUseObjectProvider
        session.singleUseObjects().put(codeId, codeLifespan, codeData.serialize());
        
        // Return opaque code: {codeId}.{userSessionId}.{hash}
        String hash = org.keycloak.common.util.Base64Url.encode((codeId + ":" + userSession.getId()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return codeId + "." + userSession.getId() + "." + hash;
    }

    private Response redirectWithCode(String redirectUri, String code, String state) {
        UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
        uriBuilder.queryParam(CODE_PARAM, code);
        if (state != null) {
            uriBuilder.queryParam(STATE_PARAM, state);
        }
        
        return Response.seeOther(uriBuilder.build()).build();
    }

    private Response redirectWithError(String redirectUri, String error, String errorDescription, String state) {
        UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
        uriBuilder.queryParam(ERROR_PARAM, error);
        if (errorDescription != null) {
            uriBuilder.queryParam(ERROR_DESCRIPTION_PARAM, errorDescription);
        }
        if (state != null) {
            uriBuilder.queryParam(STATE_PARAM, state);
        }
        
        return Response.seeOther(uriBuilder.build()).build();
    }

    private Response createErrorResponse(String redirectUri, String error, String errorDescription) {
        if (redirectUri != null) {
            return redirectWithError(redirectUri, error, errorDescription, null);
        }
        
        // Return JSON error response
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\",\"error_description\":\"%s\"}", error, errorDescription))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private String extractRequestTokenId(String requestToken) {
        if (requestToken == null) {
            return null;
        }
        String[] parts = requestToken.split("\\.", 3);
        return parts.length > 0 ? parts[0] : requestToken;
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https") 
                && realm.getSslRequired().isRequired(clientConnection)) {
            throw new ErrorPageException(session, null, Response.Status.FORBIDDEN, 
                    "HTTPS required");
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new ErrorPageException(session, null, Response.Status.FORBIDDEN,
                    "Realm not enabled");
        }
    }
}

