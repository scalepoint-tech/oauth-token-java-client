package com.scalepoint.oauth_token_client;

import org.apache.commons.codec.digest.DigestUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 "client_secret" client credentials
 */
@SuppressWarnings("WeakerAccess")
public class ClientSecretCredentials implements ClientCredentials {
    private final String clientId;
    private final String clientSecret;
    private final String credentialThumbprint;

    /**
     * Creates new ClientSecretCredentials
     *
     * @param clientId     OAuth2 "client_id"
     * @param clientSecret OAuth2 "client_secret"
     */
    public ClientSecretCredentials(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.credentialThumbprint = DigestUtils.sha1Hex(clientId + clientSecret);
    }

    @Override
    public List<NameValuePair> getPostParams() {
        ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new NameValuePair("client_id", clientId));
        params.add(new NameValuePair("client_secret", clientSecret));
        return params;
    }

    @Override
    public String getCredentialThumbprint() {
        return credentialThumbprint;
    }
}
