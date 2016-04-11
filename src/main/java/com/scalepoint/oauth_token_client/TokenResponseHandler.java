package com.scalepoint.oauth_token_client;

import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

class TokenResponseHandler implements ResponseHandler<String> {

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

}
