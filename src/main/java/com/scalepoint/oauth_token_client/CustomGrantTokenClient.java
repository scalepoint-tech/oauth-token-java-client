package com.scalepoint.oauth_token_client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public abstract class CustomGrantTokenClient {
    private final ClientCredentials clientCredentials;
    private final TokenEndpointHttpClient tokenEndpointHttpClient;
    private final String partialCacheKey;
    private final TokenCache cache;

    public CustomGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials, TokenCache cache) {
        this.tokenEndpointHttpClient = new TokenEndpointHttpClient(tokenEndpointUri);
        this.clientCredentials = clientCredentials;
        this.partialCacheKey = StringUtil.join(new String[]{tokenEndpointUri, clientCredentials.getCredentialThumbprint()}, ":");
        this.cache = cache;
    }

    /**
     * Retrieve access token for the configured "client_id" and specified scopes. Request to the server is only performed if matching valid token is not in the cache
     *
     * @param parameters Grant-specific parameters
     * @param scopes     OAuth2 scopes to request
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    protected String getTokenInternal(final List<NameValuePair> parameters, final String... scopes) throws IOException, InterruptedException {

        final String scopeString =
                (scopes == null || scopes.length < 1)
                        ? null
                        : StringUtil.join(scopes, " ");

        final String cacheKey = StringUtil.join(new String[]{partialCacheKey, getGrantType(), scopeString, String.valueOf(parameters.hashCode())}, ":");

        return cache.get(cacheKey, new TokenSource() {
            @Override
            public ExpiringToken get() throws IOException, InterruptedException {

                List<NameValuePair> form = new ArrayList<NameValuePair>();

                form.add(new NameValuePair("grant_type", getGrantType()));

                form.addAll(clientCredentials.getPostParams());
                form.addAll(parameters);

                if (scopeString != null) {
                    form.add(new NameValuePair("scope", scopeString));
                }

                return tokenEndpointHttpClient.getToken(form);
            }
        });
    }

    /**
     * @return Grant type (i.e. "client_credentials")
     */
    protected abstract String getGrantType();
}
