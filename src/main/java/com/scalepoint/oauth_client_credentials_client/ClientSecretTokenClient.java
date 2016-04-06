package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

/**
 * OAuth2 Token endpoint client with client_credentials flow support using "client_secret" client authentication scheme.
 * Tokens are cached in-memory by default.
 *
 */
public class ClientSecretTokenClient implements TokenClient {

    private static class LazyCacheHolder {
        public static final TokenCache CACHE = new InMemoryTokenCache();
    }

    private final InternalClientSecretTokenClient internalTokenClient;
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
        this.internalTokenClient = new InternalClientSecretTokenClient(tokenEndpointUri, clientId, clientSecret);
        this.partialCacheKey = StringUtils.join(tokenEndpointUri, clientId, DigestUtils.sha1(clientSecret), "|");
        this.cache = cache;
    }

    /**
     * Retrieve access token for the configured "client_id" and specified scopes. Request to the server is only performed if matching valid token is not in the cache
     *
     * @param scopes One or more OAuth2 scopes to request
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    @Override
    public String getToken(final String... scopes) throws IOException {
        if (scopes == null || scopes.length < 1) {
            throw new IllegalArgumentException("At least one scope must be present");
        }
        final String scopeString = StringUtils.join(scopes, " ");
        final String cacheKey = StringUtils.join(partialCacheKey, scopeString, ":");
        return cache.get(cacheKey, new TokenSource() {
            @Override
            public ExpiringToken get() throws IOException {
                return internalTokenClient.getToken(scopes);
            }
        });
    }
}
