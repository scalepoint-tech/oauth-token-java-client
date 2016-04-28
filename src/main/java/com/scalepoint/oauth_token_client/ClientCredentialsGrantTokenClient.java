package com.scalepoint.oauth_token_client;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 Token endpoint client with "client_credentials" flow support
 * Tokens are cached in-memory by default.
 */
@SuppressWarnings("WeakerAccess")
public class ClientCredentialsGrantTokenClient extends CustomGrantTokenClient {
    private final ClientCredentials clientCredentials;

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
    public ClientCredentialsGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials, TokenCache cache) {
        super(tokenEndpointUri, clientCredentials.getCredentialThumbprint(), cache);
        this.clientCredentials = clientCredentials;
    }

    @Override
    protected List<NameValuePair> getPostParams() {
        ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new NameValuePair("grant_type", "client_credentials"));
        params.addAll(clientCredentials.getPostParams());
        return params;
    }
}
