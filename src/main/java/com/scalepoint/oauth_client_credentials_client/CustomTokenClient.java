package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

public abstract class CustomTokenClient implements TokenClient {
    private final TokenEndpointHttpClient tokenEndpointHttpClient;
    private final String partialCacheKey;
    private final TokenCache cache;

    @SuppressWarnings("WeakerAccess")
    public CustomTokenClient(String tokenEndpointUri, String partialCacheKey, TokenCache cache) {
        this.tokenEndpointHttpClient = new TokenEndpointHttpClient(tokenEndpointUri);
        this.partialCacheKey = partialCacheKey;
        this.cache = cache;
    }

    /**
     * Retrieve access token for the configured "client_id" and specified scopes. Request to the server is only performed if matching valid token is not in the cache
     *
     * @param scopes OAuth2 scopes to request
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    @Override
    public String getToken(final String... scopes) throws IOException {

        final String scopeString =
                (scopes == null || scopes.length < 1)
                        ? null
                        : StringUtils.join(scopes, " ");

        final String cacheKey = StringUtils.join(partialCacheKey, scopeString, ":");
        return cache.get(cacheKey, new TokenSource() {
            @Override
            public ExpiringToken get() throws IOException {

                Form form = Form.form();

                addCustomFields(form);

                if (scopes != null) {
                    form.add("scope", scopeString);
                }

                final List<NameValuePair> params = form.build();
                return tokenEndpointHttpClient.getToken(params);

            }
        });
    }

    protected abstract void addCustomFields(Form form);
}
