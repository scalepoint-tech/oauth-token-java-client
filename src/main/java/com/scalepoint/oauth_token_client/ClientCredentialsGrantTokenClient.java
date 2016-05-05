package com.scalepoint.oauth_token_client;

import java.io.IOException;
import java.util.Collections;

/**
 * OAuth2 Token endpoint client with "client_credentials" flow support
 * Tokens are cached in-memory by default.
 */
@SuppressWarnings("WeakerAccess")
public class ClientCredentialsGrantTokenClient extends CustomGrantTokenClient {

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri  OAuth2 Token endpoint URI
     * @param clientCredentials OAuth2 client credentials
     */
    public ClientCredentialsGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials) {
        this(tokenEndpointUri, clientCredentials, LazyCacheHolder.CACHE);
    }

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri  OAuth2 Token endpoint URI
     * @param clientCredentials OAuth2 client credentials
     * @param cache             Token cache
     */
    @SuppressWarnings("SameParameterValue")
    public ClientCredentialsGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials, TokenCache cache) {
        super(tokenEndpointUri, clientCredentials, cache);
    }

    /**
     * Retrieve access token for the configured "client_id" and specified scopes. Request to the server is only performed if matching valid token is not in the cache
     *
     * @param scopes OAuth2 scopes to request
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    @SuppressWarnings("UnusedReturnValue")
    public String getToken(final String... scopes) throws IOException {
        return getTokenInternal(Collections.<NameValuePair>emptyList(), scopes);
    }

    @Override
    protected String getGrantType() {
        return "client_credentials";
    }
}
