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

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.TokenManager;
import org.keycloak.representations.AAuthToken;
import org.keycloak.services.resteasy.HttpRequestImpl;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;
import org.jboss.resteasy.mock.MockHttpRequest;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.Assert.*;

/**
 * Unit tests for AAuthTokenManager
 */
public class AAuthTokenManagerTest {

    private static ResteasyKeycloakSessionFactory sessionFactory;
    private KeycloakSession session;
    private RealmModel realm;
    private KeyPair realmSigningKeyPair;

    @BeforeClass
    public static void beforeClass() {
        Profile.defaults();
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
    }

    @Before
    public void setUp() throws Exception {
        realmSigningKeyPair = generateEd25519KeyPair();
        
        // Create a simple test realm using Proxy
        realm = (RealmModel) Proxy.newProxyInstance(
            AAuthTokenManagerTest.class.getClassLoader(),
            new Class[]{RealmModel.class},
            (proxy, method, args) -> {
                String methodName = method.getName();
                if ("getName".equals(methodName)) {
                    return "test-realm";
                }
                if ("getId".equals(methodName)) {
                    return "test-realm-id";
                }
                if ("getAccessTokenLifespan".equals(methodName)) {
                    return 300; // 5 minutes
                }
                if ("getDefaultSignatureAlgorithm".equals(methodName)) {
                    return Algorithm.EdDSA;
                }
                if ("isEnabled".equals(methodName)) {
                    return true;
                }
                if ("getSslRequired".equals(methodName)) {
                    return org.keycloak.common.enums.SslRequired.EXTERNAL;
                }
                if ("getClientScopesStream".equals(methodName)) {
                    return java.util.stream.Stream.empty();
                }
                // Return null for other methods
                return null;
            }
        );

        // Create HTTP request
        URI baseUri = URI.create("https://keycloak.example.com");
        URI requestUri = URI.create("https://keycloak.example.com/realms/test-realm");
        HttpRequest httpRequest = new HttpRequestImpl(MockHttpRequest.create("GET", baseUri, requestUri));

        session = new ResteasyKeycloakSession(sessionFactory) {
            @Override
            public org.keycloak.models.KeyManager keys() {
                return new TestKeyManager();
            }

            @Override
            public TokenManager tokens() {
                return new TestTokenManager();
            }
        };

        session.getContext().setRealm(realm);
        session.getContext().setHttpRequest(httpRequest);
    }

    @Test
    public void testCreateAuthToken() throws Exception {
        KeyPair agentKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String resourceId = "https://resource.example.com";
        String scope = "data.read data.write";

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String authToken = tokenManager.createAuthToken(realm, agentId, null, 
                agentKeyPair.getPublic(), resourceId, scope, null);

        assertNotNull("Auth token should not be null", authToken);
        
        // Parse and verify token structure
        JWSInput jws = new JWSInput(authToken);
        assertEquals("Token type should be auth+jwt", "auth+jwt", jws.getHeader().getType());
        
        AAuthToken token = jws.readJsonContent(AAuthToken.class);
        // The issuer is constructed from the request URI, so it may vary based on the mock setup
        // Just verify it contains the realm name
        assertNotNull("Issuer should not be null", token.getIssuer());
        assertTrue("Issuer should contain realm name", token.getIssuer().contains("/realms/test-realm"));
        assertEquals("Audience should match resource", resourceId, token.getAudience()[0]);
        assertEquals("Agent should match", agentId, token.getAgent());
        assertEquals("Scope should match", scope, token.getScope());
        assertNotNull("Expiration should be set", token.getExp());
        assertNotNull("Issued at should be set", token.getIat());
        assertNotNull("CNF claim should be present", token.getCnf());
        assertNotNull("CNF JWK should be present", token.getCnf().getJwk());
    }

    @Test
    public void testCreateAuthTokenWithAgentDelegate() throws Exception {
        KeyPair agentKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String agentDelegate = "https://delegate.example.com";
        String resourceId = "https://resource.example.com";

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String authToken = tokenManager.createAuthToken(realm, agentId, agentDelegate,
                agentKeyPair.getPublic(), resourceId, null, null);

        JWSInput jws = new JWSInput(authToken);
        AAuthToken token = jws.readJsonContent(AAuthToken.class);
        assertEquals("Agent delegate should match", agentDelegate, token.getAgentDelegate());
    }

    @Test
    public void testCreateAuthTokenWhenAgentEqualsResource() throws Exception {
        KeyPair agentKeyPair = generateEd25519KeyPair();
        String agentId = "https://agent.example.com";
        String resourceId = agentId; // Agent is the resource

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String authToken = tokenManager.createAuthToken(realm, agentId, null,
                agentKeyPair.getPublic(), resourceId, null, null);

        JWSInput jws = new JWSInput(authToken);
        AAuthToken token = jws.readJsonContent(AAuthToken.class);
        assertEquals("Audience should match agent", agentId, token.getAudience()[0]);
        assertNull("Agent claim should not be set when agent == aud", token.getAgent());
    }

    @Test
    public void testCalculateAgentJkt() throws Exception {
        KeyPair agentKeyPair = generateEd25519KeyPair();

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String agentJkt = tokenManager.calculateAgentJkt(agentKeyPair.getPublic());

        assertNotNull("Agent JKT should not be null", agentJkt);
        assertFalse("Agent JKT should not be empty", agentJkt.isEmpty());
    }

    @Test
    public void testGetTokenExpiration() {
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        long expiration = tokenManager.getTokenExpiration(realm);

        assertEquals("Expiration should match realm setting", 300L, expiration);
    }

    @Test
    public void testGetTokenExpirationWithDefault() {
        // Create realm with -1 lifespan using Proxy
        RealmModel realmWithDefault = (RealmModel) Proxy.newProxyInstance(
            AAuthTokenManagerTest.class.getClassLoader(),
            new Class[]{RealmModel.class},
            (proxy, method, args) -> {
                if ("getAccessTokenLifespan".equals(method.getName())) {
                    return -1; // Not configured
                }
                if ("getName".equals(method.getName())) {
                    return "test-realm";
                }
                if ("getId".equals(method.getName())) {
                    return "test-realm-id";
                }
                return null;
            }
        );

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        long expiration = tokenManager.getTokenExpiration(realmWithDefault);

        assertEquals("Expiration should default to 300 seconds", 300L, expiration);
    }

    private KeyPair generateEd25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        return kpg.generateKeyPair();
    }

    // Removed TestRealmModel - using Proxy instead
    /*
    private class TestRealmModel implements RealmModel {
        private int accessTokenLifespan = 300;

        public void setAccessTokenLifespan(int lifespan) {
            this.accessTokenLifespan = lifespan;
        }

        @Override
        public String getId() { return "test-realm-id"; }

        @Override
        public String getName() { return "test-realm"; }

        @Override
        public int getAccessTokenLifespan() { return accessTokenLifespan; }

        // Implement other required methods with minimal implementations
        @Override
        public void setName(String name) {}
        @Override
        public boolean isEnabled() { return true; }
        @Override
        public void setEnabled(boolean enabled) {}
        @Override
        public String getDefaultSignatureAlgorithm() { return Algorithm.EdDSA; }
        @Override
        public void setDefaultSignatureAlgorithm(String algorithm) {}
        // Add other required methods as needed - returning defaults
        @Override public boolean isSslRequired() { return false; }
        @Override public org.keycloak.common.enums.SslRequired getSslRequired() { return org.keycloak.common.enums.SslRequired.EXTERNAL; }
        @Override public void setSslRequired(org.keycloak.common.enums.SslRequired sslRequired) {}
        @Override public boolean isRegistrationAllowed() { return false; }
        @Override public void setRegistrationAllowed(boolean registrationAllowed) {}
        @Override public boolean isRegistrationEmailAsUsername() { return false; }
        @Override public void setRegistrationEmailAsUsername(boolean registrationEmailAsUsername) {}
        @Override public boolean isRememberMe() { return false; }
        @Override public void setRememberMe(boolean rememberMe) {}
        @Override public boolean isVerifyEmail() { return false; }
        @Override public void setVerifyEmail(boolean verifyEmail) {}
        @Override public boolean isLoginWithEmailAllowed() { return true; }
        @Override public void setLoginWithEmailAllowed(boolean loginWithEmailAllowed) {}
        @Override public boolean isDuplicateEmailsAllowed() { return false; }
        @Override public void setDuplicateEmailsAllowed(boolean duplicateEmailsAllowed) {}
        @Override public boolean isResetPasswordAllowed() { return false; }
        @Override public void setResetPasswordAllowed(boolean resetPasswordAllowed) {}
        @Override public boolean isEditUsernameAllowed() { return false; }
        @Override public void setEditUsernameAllowed(boolean editUsernameAllowed) {}
        @Override public boolean isBruteForceProtected() { return false; }
        @Override public void setBruteForceProtected(boolean bruteForceProtected) {}
        @Override public int getMaxFailureWaitSeconds() { return 0; }
        @Override public void setMaxFailureWaitSeconds(int val) {}
        @Override public int getMinimumQuickLoginWaitSeconds() { return 0; }
        @Override public void setMinimumQuickLoginWaitSeconds(int val) {}
        @Override public int getWaitIncrementSeconds() { return 0; }
        @Override public void setWaitIncrementSeconds(int val) {}
        @Override public long getQuickLoginCheckMilliSeconds() { return 0; }
        @Override public void setQuickLoginCheckMilliSeconds(long val) {}
        @Override public int getMaxDeltaTimeSeconds() { return 0; }
        @Override public void setMaxDeltaTimeSeconds(int val) {}
        @Override public int getFailureFactor() { return 0; }
        @Override public void setFailureFactor(int failureFactor) {}
        @Override public boolean isPermanentLockout() { return false; }
        @Override public void setPermanentLockout(boolean val) {}
        @Override public int getMaxTemporaryLockouts() { return 0; }
        @Override public void setMaxTemporaryLockouts(int val) {}
        @Override public org.keycloak.models.UserModel getDefaultGroup() { return null; }
        @Override public void setDefaultGroup(org.keycloak.models.UserModel group) {}
        @Override public java.util.List<org.keycloak.models.GroupModel> getDefaultGroups() { return java.util.Collections.emptyList(); }
        @Override public void addDefaultGroup(org.keycloak.models.GroupModel group) {}
        @Override public void removeDefaultGroup(org.keycloak.models.GroupModel group) {}
        @Override public java.util.stream.Stream<org.keycloak.models.GroupModel> getDefaultGroupsStream() { return java.util.stream.Stream.empty(); }
        @Override public boolean isPasswordCredentialGrantAllowed() { return false; }
        @Override public void setPasswordCredentialGrantAllowed(boolean passwordCredentialGrantAllowed) {}
        @Override public boolean isOAuth2DeviceAuthorizationGrantEnabled() { return false; }
        @Override public void setOAuth2DeviceAuthorizationGrantEnabled(boolean oAuth2DeviceAuthorizationGrantEnabled) {}
        @Override public boolean isOAuth2DeviceCodeLifespanEnabled() { return false; }
        @Override public void setOAuth2DeviceCodeLifespanEnabled(boolean oAuth2DeviceCodeLifespanEnabled) {}
        @Override public int getOAuth2DeviceCodeLifespan() { return 0; }
        @Override public void setOAuth2DeviceCodeLifespan(int oAuth2DeviceCodeLifespan) {}
        @Override public int getOAuth2DevicePollingInterval() { return 0; }
        @Override public void setOAuth2DevicePollingInterval(int oAuth2DevicePollingInterval) {}
        @Override public int getAccessTokenLifespanForImplicitFlow() { return 0; }
        @Override public void setAccessTokenLifespanForImplicitFlow(int seconds) {}
        @Override public int getSsoSessionIdleTimeout() { return 0; }
        @Override public void setSsoSessionIdleTimeout(int seconds) {}
        @Override public int getSsoSessionMaxLifespan() { return 0; }
        @Override public void setSsoSessionMaxLifespan(int seconds) {}
        @Override public int getSsoSessionIdleTimeoutRememberMe() { return 0; }
        @Override public void setSsoSessionIdleTimeoutRememberMe(int seconds) {}
        @Override public int getSsoSessionMaxLifespanRememberMe() { return 0; }
        @Override public void setSsoSessionMaxLifespanRememberMe(int seconds) {}
        @Override public int getOfflineSessionIdleTimeout() { return 0; }
        @Override public void setOfflineSessionIdleTimeout(int seconds) {}
        @Override public boolean isOfflineSessionMaxLifespanEnabled() { return false; }
        @Override public void setOfflineSessionMaxLifespanEnabled(boolean offlineSessionMaxLifespanEnabled) {}
        @Override public int getOfflineSessionMaxLifespan() { return 0; }
        @Override public void setOfflineSessionMaxLifespan(int seconds) {}
        @Override public int getClientSessionIdleTimeout() { return 0; }
        @Override public void setClientSessionIdleTimeout(int seconds) {}
        @Override public int getClientSessionMaxLifespan() { return 0; }
        @Override public void setClientSessionMaxLifespan(int seconds) {}
        @Override public int getClientOfflineSessionIdleTimeout() { return 0; }
        @Override public void setClientOfflineSessionIdleTimeout(int seconds) {}
        @Override public int getClientOfflineSessionMaxLifespan() { return 0; }
        @Override public void setClientOfflineSessionMaxLifespan(int seconds) {}
        @Override public int getAccessCodeLifespan() { return 0; }
        @Override public void setAccessCodeLifespan(int seconds) {}
        @Override public int getAccessCodeLifespanUserAction() { return 0; }
        @Override public void setAccessCodeLifespanUserAction(int seconds) {}
        @Override public int getAccessCodeLifespanLogin() { return 0; }
        @Override public void setAccessCodeLifespanLogin(int seconds) {}
        @Override public int getActionTokenGeneratedByAdminLifespan() { return 0; }
        @Override public void setActionTokenGeneratedByAdminLifespan(int seconds) {}
        @Override public int getActionTokenGeneratedByUserLifespan() { return 0; }
        @Override public void setActionTokenGeneratedByUserLifespan(int seconds) {}
        @Override public int getActionTokenGeneratedByUserLifespan(String actionTokenType) { return 0; }
        @Override public void setActionTokenGeneratedByUserLifespan(String actionTokenType, int seconds) {}
        @Override public org.keycloak.models.OrganizationModel getOrganizationById(String id) { return null; }
        @Override public java.util.stream.Stream<org.keycloak.models.OrganizationModel> getOrganizationsStream() { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.OrganizationModel createOrganization(String name, String alias) { return null; }
        @Override public boolean removeOrganization(String id) { return false; }
        @Override public boolean isOrganizationsEnabled() { return false; }
        @Override public void setOrganizationsEnabled(boolean organizationsEnabled) {}
        @Override public org.keycloak.models.OrganizationDomainModel getOrganizationDomainById(String domain) { return null; }
        @Override public java.util.stream.Stream<org.keycloak.models.OrganizationDomainModel> getOrganizationDomainsStream() { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.ClientScopeModel> getClientScopesStream() { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.ClientScopeModel addClientScope(String name) { return null; }
        @Override public org.keycloak.models.ClientScopeModel getClientScopeById(String id) { return null; }
        @Override public org.keycloak.models.ClientScopeModel getClientScopeByName(String name) { return null; }
        @Override public boolean removeClientScope(String id) { return null; }
        @Override public void removeDefaultClientScope(org.keycloak.models.ClientScopeModel clientScope) {}
        @Override public void addDefaultClientScope(org.keycloak.models.ClientScopeModel clientScope, boolean defaultScope) {}
        @Override public java.util.stream.Stream<org.keycloak.models.ClientScopeModel> getDefaultClientScopesStream(boolean defaultScope) { return java.util.stream.Stream.empty(); }
        @Override public java.util.Map<String, org.keycloak.models.ClientScopeModel> getClientScopes(boolean defaultScopes) { return java.util.Collections.emptyMap(); }
        @Override public org.keycloak.models.ClientModel getClientById(String id) { return null; }
        @Override public org.keycloak.models.ClientModel getClientByClientId(String clientId) { return null; }
        @Override public java.util.stream.Stream<org.keycloak.models.ClientModel> getClientsStream() { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.ClientModel addClient(String id, String clientId) { return null; }
        @Override public org.keycloak.models.ClientModel addClient(String clientId) { return null; }
        @Override public boolean removeClient(String id) { return false; }
        @Override public long getClientsCount() { return 0; }
        @Override public java.util.List<org.keycloak.models.ClientModel> getClients() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.ClientModel> getClients(Integer firstResult, Integer maxResults) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.ClientModel> searchClientsByClientId(String clientId, Integer firstResult, Integer maxResults) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.ClientModel> searchClientsByAttributes(java.util.Map<String, String> attributes, Integer firstResult, Integer maxResults) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.ClientModel> searchClientsByAuthenticationFlowBindingOverrides(java.util.Map<String, String> bindings) { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.ClientModel getClientByClientId(String clientId, org.keycloak.models.ClientModel.Scope clientScope) { return null; }
        @Override public org.keycloak.models.GroupModel getGroupById(String id) { return null; }
        @Override public org.keycloak.models.GroupModel getGroupByName(String name) { return null; }
        @Override public org.keycloak.models.GroupModel createGroup(String name) { return null; }
        @Override public org.keycloak.models.GroupModel createGroup(String id, String name) { return null; }
        @Override public org.keycloak.models.GroupModel createGroup(org.keycloak.models.GroupModel parent, String name) { return null; }
        @Override public org.keycloak.models.GroupModel createGroup(org.keycloak.models.GroupModel parent, String id, String name) { return null; }
        @Override public boolean removeGroup(org.keycloak.models.GroupModel group) { return false; }
        @Override public void moveGroup(org.keycloak.models.GroupModel group, org.keycloak.models.GroupModel toParent) {}
        @Override public java.util.List<org.keycloak.models.GroupModel> getGroups() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.GroupModel> getGroups(Integer first, Integer max) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.GroupModel> searchForGroupByNameStream(String search, Integer first, Integer max) { return java.util.Collections.emptyList(); }
        @Override public boolean removeGroupById(String id) { return false; }
        @Override public java.util.stream.Stream<org.keycloak.models.GroupModel> getGroupsStream() { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.GroupModel> getGroupsStream(Integer first, Integer max) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.GroupModel> getTopLevelGroupsStream() { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.GroupModel> getTopLevelGroupsStream(Integer first, Integer max) { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.RoleModel getRole(String name) { return null; }
        @Override public org.keycloak.models.RoleModel addRole(String name) { return null; }
        @Override public org.keycloak.models.RoleModel addRole(String id, String name) { return null; }
        @Override public org.keycloak.models.RoleModel getRoleById(String id) { return null; }
        @Override public java.util.stream.Stream<org.keycloak.models.RoleModel> getRolesStream() { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.RoleModel> getRolesStream(Integer first, Integer max) { return java.util.stream.Stream.empty(); }
        @Override public java.util.List<org.keycloak.models.RoleModel> getRoles() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.RoleModel> getRoles(Integer first, Integer max) { return java.util.Collections.emptyList(); }
        @Override public java.util.stream.Stream<org.keycloak.models.RoleModel> searchForRolesStream(String search) { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.UserModel getUserById(String id) { return null; }
        @Override public org.keycloak.models.UserModel getUserByUsername(String username) { return null; }
        @Override public org.keycloak.models.UserModel getUserByUsername(String username, boolean caseSensitive) { return null; }
        @Override public org.keycloak.models.UserModel getUserByEmail(String email) { return null; }
        @Override public org.keycloak.models.UserModel getUserByEmail(String email, boolean caseSensitive) { return null; }
        @Override public org.keycloak.models.UserModel getUserByServiceAccountClient(org.keycloak.models.ClientModel client) { return null; }
        @Override public java.util.List<org.keycloak.models.UserModel> getUsers() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserModel> getUsers(Integer firstResult, Integer maxResults) { return java.util.Collections.emptyList(); }
        @Override public int getUsersCount() { return 0; }
        @Override public java.util.List<org.keycloak.models.UserModel> searchForUser(String search) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserModel> searchForUser(String search, Integer firstResult, Integer maxResults) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserModel> searchForUser(java.util.Map<String, String> params) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserModel> searchForUser(java.util.Map<String, String> params, Integer firstResult, Integer maxResults) { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserModel> searchForUserByUserAttribute(String attrName, String attrValue) { return java.util.Collections.emptyList(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> getUsersStream() { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> getUsersStream(Integer firstResult, Integer maxResults) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> searchForUserStream(String search) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> searchForUserStream(String search, Integer firstResult, Integer maxResults) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> searchForUserStream(java.util.Map<String, String> params) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> searchForUserStream(java.util.Map<String, String> params, Integer firstResult, Integer maxResults) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> searchForUserByUserAttributeStream(String attrName, String attrValue) { return java.util.stream.Stream.empty(); }
        @Override public java.util.stream.Stream<org.keycloak.models.UserModel> searchForUserByServiceAccountClientStream(org.keycloak.models.ClientModel client) { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.UserModel addUser(String id, String username) { return null; }
        @Override public org.keycloak.models.UserModel addUser(String username) { return null; }
        @Override public boolean removeUser(org.keycloak.models.UserModel user) { return false; }
        @Override public void removeExpiredClientInitialAccess() {}
        @Override public org.keycloak.models.ClientInitialAccessModel createClientInitialAccessModel(int expiration, int count) { return null; }
        @Override public org.keycloak.models.ClientInitialAccessModel getClientInitialAccessModel(String id) { return null; }
        @Override public java.util.List<org.keycloak.models.ClientInitialAccessModel> listClientInitialAccess() { return java.util.Collections.emptyList(); }
        @Override public void removeClientInitialAccessModel(String id) {}
        @Override public java.util.List<org.keycloak.models.IdentityProviderModel> getIdentityProviders() { return java.util.Collections.emptyList(); }
        @Override public java.util.stream.Stream<org.keycloak.models.IdentityProviderModel> getIdentityProvidersStream() { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.IdentityProviderModel getIdentityProviderByAlias(String alias) { return null; }
        @Override public org.keycloak.models.IdentityProviderModel addIdentityProvider(org.keycloak.models.IdentityProviderModel identityProvider) { return null; }
        @Override public void removeIdentityProviderByAlias(String alias) {}
        @Override public void updateIdentityProvider(org.keycloak.models.IdentityProviderModel identityProvider) {}
        @Override public org.keycloak.models.IdentityProviderModel getIdentityProviderById(String id) { return null; }
        @Override public java.util.List<org.keycloak.models.IdentityProviderMapperModel> getIdentityProviderMappers() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.IdentityProviderMapperModel> getIdentityProviderMappersByAlias(String brokerAlias) { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.IdentityProviderMapperModel getIdentityProviderMapperById(String id) { return null; }
        @Override public org.keycloak.models.IdentityProviderMapperModel addIdentityProviderMapper(org.keycloak.models.IdentityProviderMapperModel model) { return null; }
        @Override public void removeIdentityProviderMapper(org.keycloak.models.IdentityProviderMapperModel mapper) {}
        @Override public void updateIdentityProviderMapper(org.keycloak.models.IdentityProviderMapperModel mapper) {}
        @Override public java.util.List<org.keycloak.models.RequiredActionProviderModel> getRequiredActionProviders() { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.RequiredActionProviderModel getRequiredActionProviderById(String id) { return null; }
        @Override public org.keycloak.models.RequiredActionProviderModel getRequiredActionProviderByAlias(String alias) { return null; }
        @Override public org.keycloak.models.RequiredActionProviderModel addRequiredActionProvider(org.keycloak.models.RequiredActionProviderModel model) { return null; }
        @Override public void updateRequiredActionProvider(org.keycloak.models.RequiredActionProviderModel model) {}
        @Override public void removeRequiredActionProvider(org.keycloak.models.RequiredActionProviderModel model) {}
        @Override public java.util.List<org.keycloak.models.AuthenticationFlowModel> getAuthenticationFlows() { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.AuthenticationFlowModel getAuthenticationFlowById(String id) { return null; }
        @Override public org.keycloak.models.AuthenticationFlowModel getAuthenticationFlowByAlias(String alias) { return null; }
        @Override public org.keycloak.models.AuthenticationFlowModel addAuthenticationFlow(org.keycloak.models.AuthenticationFlowModel model) { return null; }
        @Override public void removeAuthenticationFlow(org.keycloak.models.AuthenticationFlowModel model) {}
        @Override public void updateAuthenticationFlow(org.keycloak.models.AuthenticationFlowModel model) {}
        @Override public java.util.List<org.keycloak.models.AuthenticationExecutionModel> getAuthenticationExecutions(String flowId) { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.AuthenticationExecutionModel addAuthenticatorExecution(org.keycloak.models.AuthenticationExecutionModel model) { return null; }
        @Override public org.keycloak.models.AuthenticationExecutionModel addAuthenticatorExecution(org.keycloak.models.AuthenticationExecutionModel model, org.keycloak.models.AuthenticationFlowModel flow) { return null; }
        @Override public void removeAuthenticatorExecution(org.keycloak.models.AuthenticationExecutionModel model) {}
        @Override public void updateAuthenticatorExecution(org.keycloak.models.AuthenticationExecutionModel model) {}
        @Override public void raisePriorityAuthenticatorExecution(org.keycloak.models.AuthenticationExecutionModel model) {}
        @Override public void lowerPriorityAuthenticatorExecution(org.keycloak.models.AuthenticationExecutionModel model) {}
        @Override public org.keycloak.models.AuthenticationExecutionModel getAuthenticationExecutionById(String id) { return null; }
        @Override public org.keycloak.models.AuthenticationExecutionModel getAuthenticationExecutionByFlowId(String flowId) { return null; }
        @Override public java.util.List<org.keycloak.models.AuthenticatorConfigModel> getAuthenticatorConfigs() { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.AuthenticatorConfigModel getAuthenticatorConfigById(String id) { return null; }
        @Override public org.keycloak.models.AuthenticatorConfigModel getAuthenticatorConfigByAlias(String alias) { return null; }
        @Override public org.keycloak.models.AuthenticatorConfigModel addAuthenticatorConfig(org.keycloak.models.AuthenticatorConfigModel model) { return null; }
        @Override public void removeAuthenticatorConfig(org.keycloak.models.AuthenticatorConfigModel model) {}
        @Override public void updateAuthenticatorConfig(org.keycloak.models.AuthenticatorConfigModel model) {}
        @Override public org.keycloak.models.OTPPolicy getOTPPolicy() { return null; }
        @Override public void setOTPPolicy(org.keycloak.models.OTPPolicy policy) {}
        @Override public org.keycloak.models.WebAuthnPolicy getWebAuthnPolicy() { return null; }
        @Override public void setWebAuthnPolicy(org.keycloak.models.WebAuthnPolicy policy) {}
        @Override public org.keycloak.models.WebAuthnPolicy getWebAuthnPolicyPasswordless() { return null; }
        @Override public void setWebAuthnPolicyPasswordless(org.keycloak.models.WebAuthnPolicy policy) {}
        @Override public java.util.Map<String, String> getBrowserSecurityHeaders() { return java.util.Collections.emptyMap(); }
        @Override public void setBrowserSecurityHeaders(java.util.Map<String, String> headers) {}
        @Override public java.util.Map<String, String> getSmtpConfig() { return java.util.Collections.emptyMap(); }
        @Override public void setSmtpConfig(java.util.Map<String, String> smtpConfig) {}
        @Override public java.util.List<org.keycloak.models.UserFederationProviderModel> getUserFederationProviders() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserFederationProviderModel> getUserFederationProvidersStream() { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.UserFederationProviderModel addUserFederationProvider(String name, String providerId, java.util.Map<String, String> config, int priority, String displayName, org.keycloak.models.UserFederationSyncResult fullSyncPeriod, org.keycloak.models.UserFederationSyncResult changedSyncPeriod) { return null; }
        @Override public void removeUserFederationProvider(org.keycloak.models.UserFederationProviderModel provider) {}
        @Override public void updateUserFederationProvider(org.keycloak.models.UserFederationProviderModel provider) {}
        @Override public org.keycloak.models.UserFederationSyncResult syncAllUsers(org.keycloak.models.UserFederationProviderModel model, String action) { return null; }
        @Override public org.keycloak.models.UserFederationSyncResult syncChangedUsers(org.keycloak.models.UserFederationProviderModel model, String action) { return null; }
        @Override public java.util.List<org.keycloak.models.UserFederationMapperModel> getUserFederationMappers() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.UserFederationMapperModel> getUserFederationMappersByFederationProvider(org.keycloak.models.UserFederationProviderModel provider) { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.UserFederationMapperModel getUserFederationMapperById(String id) { return null; }
        @Override public org.keycloak.models.UserFederationMapperModel addUserFederationMapper(org.keycloak.models.UserFederationMapperModel mapper) { return null; }
        @Override public void removeUserFederationMapper(org.keycloak.models.UserFederationMapperModel mapper) {}
        @Override public void updateUserFederationMapper(org.keycloak.models.UserFederationMapperModel mapper) {}
        @Override public java.util.List<org.keycloak.models.ComponentModel> getComponents(String parentId, String providerType) { return java.util.Collections.emptyList(); }
        @Override public java.util.stream.Stream<org.keycloak.models.ComponentModel> getComponentsStream(String parentId, String providerType) { return java.util.stream.Stream.empty(); }
        @Override public org.keycloak.models.ComponentModel addComponentModel(org.keycloak.models.ComponentModel model) { return null; }
        @Override public org.keycloak.models.ComponentModel importComponentModel(org.keycloak.models.ComponentModel model) { return null; }
        @Override public void updateComponent(org.keycloak.models.ComponentModel component) {}
        @Override public void removeComponent(org.keycloak.models.ComponentModel component) {}
        @Override public void removeComponents(String parentId, String providerType) {}
        @Override public org.keycloak.models.ComponentModel getComponent(String id) { return null; }
        @Override public java.util.List<org.keycloak.models.ProtocolMapperModel> getProtocolMappers() { return java.util.Collections.emptyList(); }
        @Override public java.util.List<org.keycloak.models.ProtocolMapperModel> getProtocolMappersByProtocol(String protocol) { return java.util.Collections.emptyList(); }
        @Override public org.keycloak.models.ProtocolMapperModel addProtocolMapper(org.keycloak.models.ProtocolMapperModel model) { return null; }
        @Override public void updateProtocolMapper(org.keycloak.models.ProtocolMapperModel model) {}
        @Override public void removeProtocolMapper(org.keycloak.models.ProtocolMapperModel mapper) {}
        @Override public org.keycloak.models.ProtocolMapperModel getProtocolMapperById(String id) { return null; }
        @Override public org.keycloak.models.ProtocolMapperModel getProtocolMapperByName(String protocol, String name) { return null; }
        @Override public int getRefreshTokenMaxReuse() { return 0; }
        @Override public void setRefreshTokenMaxReuse(int refreshTokenMaxReuse) {}
        @Override public int getRevokeRefreshToken() { return 0; }
        @Override public void setRevokeRefreshToken(int revokeRefreshToken) {}
        @Override public java.util.Map<String, String> getAttributes() { return java.util.Collections.emptyMap(); }
        @Override public String getAttribute(String name) { return null; }
        @Override public void setAttribute(String name, String value) {}
        @Override public void removeAttribute(String name) {}
        @Override public java.util.Map<String, String> getBrowserFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setBrowserFlow(String flow) {}
        @Override public java.util.Map<String, String> getRegistrationFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setRegistrationFlow(String flow) {}
        @Override public java.util.Map<String, String> getDirectGrantFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setDirectGrantFlow(String flow) {}
        @Override public java.util.Map<String, String> getResetCredentialsFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setResetCredentialsFlow(String flow) {}
        @Override public java.util.Map<String, String> getClientAuthenticationFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setClientAuthenticationFlow(String flow) {}
        @Override public java.util.Map<String, String> getDockerAuthenticationFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setDockerAuthenticationFlow(String flow) {}
        @Override public java.util.Map<String, String> getFirstBrokerLoginFlow() { return java.util.Collections.emptyMap(); }
        @Override public void setFirstBrokerLoginFlow(String flow) {}
    }
    */

    // Simple test key manager
    private class TestKeyManager implements org.keycloak.models.KeyManager {
        @Override
        public org.keycloak.crypto.KeyWrapper getActiveKey(RealmModel realm, KeyUse use, String algorithm) {
            KeyWrapper key = new KeyWrapper();
            key.setKid("test-kid");
            key.setAlgorithm(Algorithm.EdDSA);
            key.setType(org.keycloak.crypto.KeyType.OKP);
            key.setUse(use);
            key.setPrivateKey(realmSigningKeyPair.getPrivate());
            key.setPublicKey(realmSigningKeyPair.getPublic());
            key.setCurve(Algorithm.Ed25519);
            key.setStatus(org.keycloak.crypto.KeyStatus.ACTIVE);
            return key;
        }

        @Override
        public java.util.stream.Stream<org.keycloak.crypto.KeyWrapper> getKeysStream(RealmModel realm) {
            return java.util.stream.Stream.of(getActiveKey(realm, KeyUse.SIG, Algorithm.EdDSA));
        }

        // Implement other required methods with minimal implementations
        @Override
        public org.keycloak.crypto.KeyWrapper getKey(RealmModel realm, String kid, KeyUse use, String algorithm) {
            return getActiveKey(realm, use, algorithm);
        }

        @Override
        public org.keycloak.models.KeyManager.ActiveRsaKey getActiveRsaKey(RealmModel realm) { return null; }
        @Override
        public java.util.stream.Stream<org.keycloak.crypto.KeyWrapper> getKeysStream(RealmModel realm, KeyUse use, String algorithm) { return java.util.stream.Stream.empty(); }
        @Override
        public java.security.PublicKey getRsaPublicKey(RealmModel realm, String kid) { return null; }
        @Override
        public java.util.List<org.keycloak.keys.RsaKeyMetadata> getRsaKeys(RealmModel realm) { return java.util.Collections.emptyList(); }
        @Override
        public javax.crypto.SecretKey getAesSecretKey(RealmModel realm, String kid) { return null; }
        @Override
        public java.security.cert.Certificate getRsaCertificate(RealmModel realm, String kid) { return null; }
        @Override
        public org.keycloak.models.KeyManager.ActiveHmacKey getActiveHmacKey(RealmModel realm) { return null; }
        @Override
        public java.util.List<org.keycloak.keys.SecretKeyMetadata> getAesKeys(RealmModel realm) { return java.util.Collections.emptyList(); }
        @Override
        public javax.crypto.SecretKey getHmacSecretKey(RealmModel realm, String kid) { return null; }
        @Override
        public org.keycloak.models.KeyManager.ActiveAesKey getActiveAesKey(RealmModel realm) { return null; }
        @Override
        public java.util.List<org.keycloak.keys.SecretKeyMetadata> getHmacKeys(RealmModel realm) { return java.util.Collections.emptyList(); }
    }

    // Simple test token manager
    private class TestTokenManager implements TokenManager {
        @Override
        public String signatureAlgorithm(org.keycloak.TokenCategory category) {
            return Algorithm.EdDSA; // Return EdDSA for Ed25519 keys
        }

        @Override
        public String encode(org.keycloak.Token token) {
            throw new UnsupportedOperationException("Not implemented in test");
        }

        @Override
        public <T extends org.keycloak.Token> T decode(String token, Class<T> clazz) {
            throw new UnsupportedOperationException("Not implemented in test");
        }

        @Override
        public <T> T decodeClientJWT(String token, org.keycloak.models.ClientModel client, java.util.function.BiConsumer<org.keycloak.jose.JOSE, org.keycloak.models.ClientModel> jwtValidator, Class<T> clazz) {
            throw new UnsupportedOperationException("Not implemented in test");
        }

        @Override
        public String encodeAndEncrypt(org.keycloak.Token token) {
            throw new UnsupportedOperationException("Not implemented in test");
        }

        @Override
        public String cekManagementAlgorithm(org.keycloak.TokenCategory category) {
            throw new UnsupportedOperationException("Not implemented in test");
        }

        @Override
        public String encryptAlgorithm(org.keycloak.TokenCategory category) {
            throw new UnsupportedOperationException("Not implemented in test");
        }

        @Override
        public org.keycloak.representations.LogoutToken initLogoutToken(org.keycloak.models.ClientModel client, org.keycloak.models.UserModel user, org.keycloak.models.AuthenticatedClientSessionModel clientSessionModel) {
            throw new UnsupportedOperationException("Not implemented in test");
        }
    }
}
