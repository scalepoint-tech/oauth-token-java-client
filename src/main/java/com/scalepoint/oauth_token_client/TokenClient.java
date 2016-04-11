package com.scalepoint.oauth_token_client;

import java.io.IOException;

/**
 * OAuth2 Token client
 */
@SuppressWarnings("WeakerAccess")
public interface TokenClient {
    /**
     * Retrieve access token for specified scopes.
     *
     * @param scopes One or more OAuth2 scopes to request
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    @SuppressWarnings("UnusedReturnValue")
    String getToken(String... scopes) throws IOException;
}
