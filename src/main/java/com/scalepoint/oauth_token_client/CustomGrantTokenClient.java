package com.scalepoint.oauth_token_client;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

@SuppressWarnings("WeakerAccess")
public abstract class CustomGrantTokenClient implements TokenClient {
    private final TokenEndpointHttpClient tokenEndpointHttpClient;
    private final String partialCacheKey;
    private final TokenCache cache;

    public CustomGrantTokenClient(String tokenEndpointUri, String partialCacheKey, TokenCache cache) {
        this.tokenEndpointHttpClient = new TokenEndpointHttpClient(tokenEndpointUri);
        this.partialCacheKey = StringUtils.join(new String[]{tokenEndpointUri, partialCacheKey}, ':');
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

        final String cacheKey = StringUtils.join(new String[]{partialCacheKey, scopeString}, ':');
        return cache.get(cacheKey, new TokenSource() {
            @Override
            public ExpiringToken get() throws IOException {

                Form form = Form.form();

                for (NameValuePair pair : getPostParams()) {
                    form.add(pair.getName(), pair.getValue());
                }

                if (scopes != null) {
                    form.add("scope", scopeString);
                }

                return tokenEndpointHttpClient.getToken(form.build());
            }
        });
    }

    /**
     * @return List of token endpoint parameters excluding "scope", which is added automatically
     * <pre>
     * &#64;Override
     * {@code
     *
     *  protected List<NameValuePair> getPostParams() {
     *      ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
     *      params.add(new NameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
     *      params.add(new NameValuePair("assertion", getAssertionJwt()));
     *      return params;
     *  }
     * }
     * </pre>
     */
    protected abstract List<NameValuePair> getPostParams();
}
