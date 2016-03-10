package com.scalepoint.jwt_assertion_client;

import java.io.IOException;

/**
 * OAuth2 Token client
 */
public interface TokenClient {
    /**
     * Retrieve access token for specified scopes.
     * @param scopes One or more OAuth2 scopes to request
     * @return Access token
     * @throws IOException
     */
    String getToken(String... scopes) throws IOException;
}
