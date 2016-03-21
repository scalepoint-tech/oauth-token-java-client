package com.scalepoint.jwt_assertion_client;

import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.CharEncoding;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;

@SuppressWarnings("unused")
public class ValidRequestExpectationCallback implements ExpectationCallback {
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
        List<NameValuePair> parsedParams = URLEncodedUtils.parse(body, Charset.forName(CharEncoding.UTF_8));
        HashMap<String, String> params = new HashMap<String, String>();
        for (NameValuePair p : parsedParams) params.put(p.getName(), p.getValue());

        if (!params.get("grant_type").equals("client_credentials")) return false;
        if (!params.get("client_id").equals("clientid")) return false;
        if (!params.get("client_assertion_type").equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")) return false;
        if (!params.get("scope").equals("scope1 scope2")) return false;

        RSACertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        Jwts.parser().setSigningKey(keyPair.getPrivateKey()).parseClaimsJws(params.get("client_assertion"));

        return true;
    }
}
