package com.scalepoint.oauth_token_client;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 Token endpoint client for urn:scalepoint:params:oauth:grant-type:delegate-access grant.
 * Tokens are cached in-memory by default.
 */
public class DelegateAccessGrantTokenClient extends CustomGrantTokenClient {
    private final ClientCredentials clientCredentials;
    private final String resource;
    private final String amr;

    @SuppressWarnings("SameParameterValue")
    public DelegateAccessGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials, String resource, String amr) {
        super(tokenEndpointUri, clientCredentials.getCredentialThumbprint(), new NoCache());
        this.clientCredentials = clientCredentials;
        this.resource = resource;
        this.amr = amr;
    }

    @Override
    protected List<NameValuePair> getPostParams() {
        ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new NameValuePair("grant_type", "urn:scalepoint:params:oauth:grant-type:delegate-access"));
        params.addAll(clientCredentials.getPostParams());
        params.add(new NameValuePair("resource", resource));
        params.add(new NameValuePair("amr", amr));
        return params;
    }
}
