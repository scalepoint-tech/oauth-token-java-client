package com.scalepoint.oauth_token_client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.stream.Collectors;

class TokenEndpointHttpClient {
    private final static ObjectMapper MAPPER = new ObjectMapper();

    private final String tokenEndpointUri;
    private final HttpClient httpClient;

    public TokenEndpointHttpClient(String tokenEndpointUri) {
        this.tokenEndpointUri = tokenEndpointUri;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    ExpiringToken getToken(List<NameValuePair> params) throws IOException, InterruptedException {
        String formData = params.stream()
                .map(p -> URLEncoder.encode(p.getName(), StandardCharsets.UTF_8) + "=" + 
                         URLEncoder.encode(p.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpointUri))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formData, StandardCharsets.UTF_8))
                .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("HTTP Status Code: " + response.statusCode() + ", " + response.body());
        }
        
        return parseResponse(response.body());
    }

    private ExpiringToken parseResponse(String tokenResponse) throws IOException {
        JsonNode rootNode = MAPPER.readValue(tokenResponse, JsonNode.class);

        String accessToken = rootNode.get("access_token").asText();

        int expiresInSeconds = 0;
        JsonNode expires_in = rootNode.get("expires_in");
        if (expires_in != null) {
            expiresInSeconds = expires_in.asInt();
        }

        return new ExpiringToken(accessToken, expiresInSeconds);
    }
}
