package com.scalepoint.oauth_token_client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.List;

class TokenEndpointHttpClient {
    private final static String UTF8 = "utf-8";
    private final static ObjectMapper MAPPER = new ObjectMapper();

    private final String tokenEndpointUri;

    public TokenEndpointHttpClient(String tokenEndpointUri) {
        this.tokenEndpointUri = tokenEndpointUri;
    }

    ExpiringToken getToken(List<NameValuePair> params) throws IOException {

        String body = formatRequest(params);
        HttpURLConnection c = makeRequest(body);
        String tokenResponse = readResponse(c);
        return parseResponse(tokenResponse);
    }

    private String formatRequest(List<NameValuePair> params) throws UnsupportedEncodingException {
        String body = "";
        for (NameValuePair p: params) {
            body += URLEncoder.encode(p.getName(), UTF8) + "=" + URLEncoder.encode(p.getValue(), UTF8) + "&";
        }
        body = body.substring(0, body.length()-1);
        return body;
    }

    private HttpURLConnection makeRequest(String body) throws IOException {
        URL u = new URL(tokenEndpointUri);
        HttpURLConnection c = (HttpURLConnection)u.openConnection();
        c.setRequestMethod("POST");
        c.setInstanceFollowRedirects(false);
        c.setDoInput(true);
        c.setDoOutput(true);
        c.setReadTimeout(30 * 1000);
        c.setConnectTimeout(30 * 1000);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        c.setUseCaches(false);
        OutputStream outputStream = c.getOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(outputStream);
        writer.write(body);
        writer.flush();
        writer.close();
        return c;
    }

    private String readResponse(HttpURLConnection c) throws IOException {
        int statusCode = c.getResponseCode();
        if (statusCode != 200) {
            InputStream errorStream = c.getErrorStream();
            String errorMessage = errorStream != null
                    ? ", " + readStream(errorStream)
                    : "";
            throw new IOException("HTTP Status Code: "+statusCode+errorMessage);
        }
        return readStream(c.getInputStream());
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

    private String readStream(InputStream stream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
        String content = "";
        String line;
        while ((line = reader.readLine()) != null) {
            content += line;
        }
        reader.close();
        return content;
    }
}
