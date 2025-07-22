package com.scalepoint.oauth_token_client;

import io.jsonwebtoken.Jwts;

import java.util.HashMap;

public class ValidClientAssertionExpectationCallback extends ValidRequestExpectationCallback {
    @Override
    protected boolean isValid(HashMap<String, String> params) {

        if (!params.get("grant_type").equals("client_credentials")) return false;
        if (!params.get("scope").equals("scope1 scope2")) return false;
        if (!params.get("client_assertion_type").equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
            return false;

        CertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        Jwts.parser().verifyWith(keyPair.getCertificate().getPublicKey()).build().parseSignedClaims(params.get("client_assertion"));

        return true;
    }
}