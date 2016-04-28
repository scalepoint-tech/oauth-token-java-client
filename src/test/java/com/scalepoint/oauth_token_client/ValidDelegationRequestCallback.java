package com.scalepoint.oauth_token_client;

import io.jsonwebtoken.Jwts;

import java.util.HashMap;

public class ValidDelegationRequestCallback extends ValidRequestExpectationCallback {
    @SuppressWarnings("RedundantIfStatement")
    @Override
    protected boolean isValid(HashMap<String, String> params) {
        if (!params.get("grant_type").equals("urn:scalepoint:params:oauth:grant-type:delegate-access")) return false;
        if (!params.get("scope").equals("scope1 scope2")) return false;
        if (!params.get("client_assertion_type").equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
            return false;

        RSACertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        Jwts.parser().setSigningKey(keyPair.getPrivateKey()).parseClaimsJws(params.get("client_assertion"));

        if (!params.get("resource").equals("resource")) return false;
        if (!params.get("amr").equals("amr")) return false;

        return true;
    }
}
