package com.scalepoint.oauth_token_client;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 Token endpoint client for urn:scalepoint:params:oauth:grant-type:delegate-access grant with "private_key_jwt" client authentication scheme.
 * Tokens are cached in-memory by default.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7521#section-6.2">Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID Connect Core 1.0</a>
 */
public class DelegateAccessGrantTokenClient extends CustomGrantTokenClient {
    private final ClientCredentials clientCredentials;
    private final String resource;
    private final String amr;

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
