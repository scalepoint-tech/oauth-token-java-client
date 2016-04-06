package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

/**
 * OAuth2 Token endpoint client with client_credentials flow support using "client_secret" client authentication scheme.
 * Tokens are cached in-memory by default.
 */
public class ClientSecretTokenClient implements TokenClient {

    private final InternalTokenClient internalTokenClient;
    private final String clientId;
    private final String clientSecret;
    private final String partialCacheKey;
    private final TokenCache cache;

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri OAuth2 Token endpoint URI
     * @param clientId         OAuth2 "client_id"
     * @param clientSecret     OAuth2 "client_secret"
     */
    @SuppressWarnings({"SameParameterValue", "unused"})
    public ClientSecretTokenClient(String tokenEndpointUri, String clientId, String clientSecret) {
        this(tokenEndpointUri, clientId, clientSecret, LazyCacheHolder.CACHE);
    }

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri OAuth2 Token endpoint URI
     * @param clientId         OAuth2 "client_id"
     * @param clientSecret     OAuth2 "client_secret"
     * @param cache            Token cache
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue", "unused"})
    public ClientSecretTokenClient(String tokenEndpointUri, String clientId, String clientSecret, TokenCache cache) {
        this.internalTokenClient = new InternalTokenClient(tokenEndpointUri);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.partialCacheKey = StringUtils.join(tokenEndpointUri, clientId, DigestUtils.sha1(clientSecret), "|");
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
                Form form = Form.form()
                        .add("grant_type", "client_credentials")
                        .add("client_id", clientId)
                        .add("client_secret", clientSecret);

                if (scopeString != null) {
                    form.add("scope", StringUtils.join(scopes, " "));
                }

                final List<NameValuePair> params = form.build();
                return internalTokenClient.getToken(params);
            }
        });
    }
}
