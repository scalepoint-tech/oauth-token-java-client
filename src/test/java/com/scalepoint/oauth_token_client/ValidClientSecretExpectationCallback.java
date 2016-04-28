package com.scalepoint.oauth_token_client;

import java.util.HashMap;

public class ValidClientSecretExpectationCallback extends ValidRequestExpectationCallback {
    @SuppressWarnings("RedundantIfStatement")
    @Override
    protected boolean isValid(HashMap<String, String> params) {

        if (!params.get("grant_type").equals("client_credentials")) return false;
        if (!params.get("scope").equals("scope1 scope2")) return false;
        if (!params.get("client_id").equals("clientid")) return false;
        if (!params.get("client_secret").equals("password")) return false;

        return true;
    }
}
