package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

class InternalClientSecretTokenClient extends InternalTokenClient {
    private final String clientId;
    private final String clientSecret;

    InternalClientSecretTokenClient(String tokenEndpointUri, String clientId, String clientSecret) {
        super(tokenEndpointUri);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public ExpiringToken getToken(String... scopes) throws IOException {
        final List<NameValuePair> form = Form.form()
                .add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_secret", clientSecret)
                .add("scope", StringUtils.join(scopes, " "))
                .build();

        return super.getToken(form);
    }
}
