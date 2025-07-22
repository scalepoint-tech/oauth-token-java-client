package com.scalepoint.oauth_token_client;

import io.jsonwebtoken.Jwts;

import java.util.HashMap;

public class ValidResourceScopedAccessRequestCallback extends ValidRequestExpectationCallback {
    @Override
    protected boolean isValid(HashMap<String, String> params) {
        if (!params.get("grant_type").equals("urn:scalepoint:params:oauth:grant-type:resource-scoped-access")) return false;
        if (!params.get("scope").equals("scope")) return false;
        if (!params.get("client_assertion_type").equals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
            return false;

        CertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        Jwts.parser().verifyWith(keyPair.getCertificate().getPublicKey()).build().parseSignedClaims(params.get("client_assertion"));

        if (!params.get("resource").equals("resource")) return false;
        if (!params.get("amr").equals("pwd otp mfa")) return false;
        if (!params.get("tenantId").equals("tenantId")) return false;

        return true;
    }
}
