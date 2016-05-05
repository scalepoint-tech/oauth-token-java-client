package com.scalepoint.oauth_token_client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 Token endpoint client for urn:scalepoint:params:oauth:grant-type:resource-scoped-access grant.
 */
@SuppressWarnings("WeakerAccess")
public class ResourceScopedAccessGrantTokenClient extends CustomGrantTokenClient {

    @SuppressWarnings("SameParameterValue")
    public ResourceScopedAccessGrantTokenClient(String tokenEndpointUri, ClientCredentials clientCredentials) {
        super(tokenEndpointUri, clientCredentials, new NoCache());
    }

    /**
     * Retrieve access token for the configured "client_id", specified scope and resource
     *
     * @param parameters Custom grant parameters
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    @SuppressWarnings("UnusedReturnValue")
    public String getToken(ResourceScopedAccessGrantParameters parameters) throws IOException {
        return getTokenInternal(getPostParams(parameters), parameters.getScope());
    }

    private List<NameValuePair> getPostParams(ResourceScopedAccessGrantParameters parameters) {
        ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new NameValuePair("resource", parameters.getResource()));
        String tenantId = parameters.getTenantId();
        if (tenantId != null) {
            params.add(new NameValuePair("tenantId", tenantId));
        }
        String amr = parameters.getAmrString();
        if (amr != null) {
            params.add(new NameValuePair("amr", amr));
        }
        return params;
    }

    @Override
    protected String getGrantType() {
        return "urn:scalepoint:params:oauth:grant-type:resource-scoped-access";
    }
}
