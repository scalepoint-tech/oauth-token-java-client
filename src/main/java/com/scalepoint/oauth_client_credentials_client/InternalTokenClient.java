package com.scalepoint.oauth_client_credentials_client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.CharEncoding;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Request;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;

class InternalTokenClient {

    private final String tokenEndpointUri;

    public InternalTokenClient(String tokenEndpointUri) {
        this.tokenEndpointUri = tokenEndpointUri;
    }

    ExpiringToken getToken(List<NameValuePair> params) throws IOException {
        final String tokenResponse = Request.Post(tokenEndpointUri)
                .bodyForm(params, Charset.forName(CharEncoding.UTF_8))
                .socketTimeout(15 * 1000)
                .connectTimeout(15 * 1000)
                .execute()
                .handleResponse(new TokenResponseHandler());

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readValue(tokenResponse, JsonNode.class);

        String accessToken = rootNode.get("access_token").asText();

        int expiresInSeconds = 0;
        JsonNode expires_in = rootNode.get("expires_in");
        if (expires_in != null) {
            expiresInSeconds = expires_in.asInt();
        }

        return new ExpiringToken(accessToken, expiresInSeconds);
    }
}
