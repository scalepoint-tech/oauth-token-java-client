package com.scalepoint.oauth_token_client;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.mockserver.mock.action.ExpectationResponseCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

abstract class ValidRequestExpectationCallback implements ExpectationResponseCallback {
    @Override
    public HttpResponse handle(HttpRequest httpRequest) {

        if (isValid(httpRequest)) {
            return new SuccessfulExpectationCallback().handle(httpRequest);
        } else {
            return new BadRequestCallback().handle(httpRequest);
        }
    }

    private boolean isValid(HttpRequest httpRequest) {
        String body = (String) httpRequest.getBody().getValue();
        List<NameValuePair> parsedParams = URLEncodedUtils.parse(body, StandardCharsets.UTF_8);
        HashMap<String, String> params = new HashMap<String, String>();
        for (NameValuePair p : parsedParams) params.put(p.getName(), p.getValue());
        return isValid(params);
    }

    protected abstract boolean isValid(HashMap<String, String> params);
}
