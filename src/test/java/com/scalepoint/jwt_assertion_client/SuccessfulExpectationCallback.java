package com.scalepoint.jwt_assertion_client;

import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

@SuppressWarnings("WeakerAccess")
public class SuccessfulExpectationCallback implements ExpectationCallback {
    @Override
    public HttpResponse handle(HttpRequest httpRequest) {
        return new HttpResponse()
                .withStatusCode(200)
                .withHeaders(
                        new Header("Content-Type", "application/json; charset=utf-8")
                )
                .withBody("{\"access_token\": \"here you go!\", \"token_type\": \"Bearer\", \"expires_in\": \"1800\"}");
    }
}

