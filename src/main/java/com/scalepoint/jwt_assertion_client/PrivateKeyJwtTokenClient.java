package com.scalepoint.jwt_assertion_client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;

import java.io.IOException;

class PrivateKeyJwtTokenClient {
    private final String tokenEndpointUri;
    private final String clientId;
    private final JwtAssertionFactory assertionFactory;

    public PrivateKeyJwtTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair) {
        this.tokenEndpointUri = tokenEndpointUri;
        this.clientId = clientId;
        this.assertionFactory = new JwtAssertionFactory(tokenEndpointUri, clientId, keyPair);
    }

    public ExpiringToken getToken(String... scopes) throws IOException {
        String assertionToken = assertionFactory.CreateAssertionToken();

        String tokenResponse = Request.Post(tokenEndpointUri)
                .bodyForm(
                        Form.form()
                                .add("grant_type", "client_credentials")
                                .add("client_id", clientId)
                                .add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                                .add("client_assertion", assertionToken)
                                .add("scope", StringUtils.join(scopes, " "))
                                .build()
                )
                .execute()
                .returnContent()
                .asString();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readValue(tokenResponse, JsonNode.class);

        String accessToken = rootNode.get("access_token").asText();
        int expiresInSeconds = rootNode.get("expires_in").asInt();

        return new ExpiringToken(accessToken, expiresInSeconds);
    }
}
