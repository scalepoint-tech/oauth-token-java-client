package com.scalepoint.jwt_assertion_client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.CharEncoding;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.Charset;

class InternalJwtAssertionTokenClient {
    private final String tokenEndpointUri;
    private final String clientId;
    private final JwtAssertionFactory assertionFactory;

    InternalJwtAssertionTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair) {
        this.tokenEndpointUri = tokenEndpointUri;
        this.clientId = clientId;
        this.assertionFactory = new JwtAssertionFactory(tokenEndpointUri, clientId, keyPair);
    }

    public ExpiringToken getToken(String... scopes) throws IOException {
        String assertionToken = assertionFactory.CreateAssertionToken();

        final String tokenResponse = Request.Post(tokenEndpointUri)
                .bodyForm(
                        Form.form()
                                .add("grant_type", "client_credentials")
                                .add("client_id", clientId)
                                .add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                                .add("client_assertion", assertionToken)
                                .add("scope", StringUtils.join(scopes, " "))
                                .build(),
                        Charset.forName(CharEncoding.UTF_8)
                )
                .socketTimeout(15 * 1000)
                .connectTimeout(15 * 1000)
                .execute()
                .handleResponse(new ResponseHandler<String>() {
                    @Override
                    public String handleResponse(HttpResponse httpResponse) throws IOException {
                        String body = EntityUtils.toString(httpResponse.getEntity());
                        StatusLine statusLine = httpResponse.getStatusLine();
                        int statusCode = statusLine.getStatusCode();
                        if (statusCode != 200) {
                            String reasonPhrase = statusLine.getReasonPhrase();
                            // include token endpoint error in the message
                            String errorMessage = statusCode != 400
                                    ? reasonPhrase
                                    : reasonPhrase + ": " + body;
                            throw new HttpResponseException(statusCode, errorMessage);
                        }
                        return body;
                    }
                });

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readValue(tokenResponse, JsonNode.class);

        String accessToken = rootNode.get("access_token").asText();
        int expiresInSeconds = rootNode.get("expires_in").asInt();

        return new ExpiringToken(accessToken, expiresInSeconds);
    }
}
