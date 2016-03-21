package com.scalepoint.jwt_assertion_client;

import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

@SuppressWarnings("WeakerAccess")
public class BadRequestCallback implements ExpectationCallback {
    @Override
    public HttpResponse handle(HttpRequest httpRequest) {
        return new HttpResponse()
                .withStatusCode(400)
                .withHeaders(
                        new Header("Content-Type", "application/json; charset=utf-8")
                )
                .withBody("{\"error\": \"invalid_client\"}");
    }
}
