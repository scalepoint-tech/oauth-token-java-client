package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.fluent.Form;

/**
 * OAuth2 Token endpoint client with client_credentials flow support using "client_secret" client authentication scheme.
 * Tokens are cached in-memory by default.
 */
public class ClientSecretTokenClient extends CustomTokenClient {

    private final String clientId;
    private final String clientSecret;

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
        super(tokenEndpointUri, StringUtils.join(tokenEndpointUri, clientId, DigestUtils.sha1(clientSecret), "|"), cache);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    protected void addCustomFields(Form form) {
        form.add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_secret", clientSecret);
    }
}
