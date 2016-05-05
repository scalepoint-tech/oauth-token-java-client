package com.scalepoint.oauth_token_client;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

@SuppressWarnings("WeakerAccess")
public abstract class CustomGrantTokenClient {
    private final ClientCredentials clientCredentials;
    private final TokenEndpointHttpClient tokenEndpointHttpClient;
    private final String partialCacheKey;
    private final TokenCache cache;

    public CustomGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials, TokenCache cache) {
        this.tokenEndpointHttpClient = new TokenEndpointHttpClient(tokenEndpointUri);
        this.clientCredentials = clientCredentials;
        this.partialCacheKey = StringUtils.join(new String[]{tokenEndpointUri, clientCredentials.getCredentialThumbprint()}, ':');
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
    protected String getTokenInternal(final List<NameValuePair> parameters, final String... scopes) throws IOException {

        final String scopeString =
                (scopes == null || scopes.length < 1)
                        ? null
                        : StringUtils.join(scopes, " ");

        final String cacheKey = StringUtils.join(new String[]{partialCacheKey, getGrantType(), scopeString, String.valueOf(parameters.hashCode())}, ':');

        return cache.get(cacheKey, new TokenSource() {
            @Override
            public ExpiringToken get() throws IOException {

                Form form = Form.form();

                form.add("grant_type", getGrantType());

                for (NameValuePair pair : clientCredentials.getPostParams()) {
                    form.add(pair.getName(), pair.getValue());
                }

                for (NameValuePair pair : parameters) {
                    form.add(pair.getName(), pair.getValue());
                }

                if (scopeString != null) {
                    form.add("scope", scopeString);
                }

                return tokenEndpointHttpClient.getToken(form.build());
            }
        });
    }

    /**
     * @return Grant type (i.e. "client_credentials")
     */
    protected abstract String getGrantType();
}
