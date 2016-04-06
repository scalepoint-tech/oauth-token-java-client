package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

class InternalJwtAssertionTokenClient extends InternalTokenClient {
    private final String clientId;
    private final JwtAssertionFactory assertionFactory;

    InternalJwtAssertionTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair) {
        super(tokenEndpointUri);
        this.clientId = clientId;
        this.assertionFactory = new JwtAssertionFactory(tokenEndpointUri, clientId, keyPair);
    }

    public ExpiringToken getToken(String... scopes) throws IOException {
        String assertionToken = assertionFactory.CreateAssertionToken();

        final List<NameValuePair> form = Form.form()
                .add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .add("client_assertion", assertionToken)
                .add("scope", StringUtils.join(scopes, " "))
                .build();

        return super.getToken(form);
    }
}
