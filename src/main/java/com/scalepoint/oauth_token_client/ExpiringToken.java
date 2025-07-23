package com.scalepoint.oauth_token_client;

/**
 * Container for token and its expiration in seconds
 */
public class ExpiringToken {
    private final String token;
    private final int expiresInSeconds;

    /**
     * Create new container
     *
     * @param token            Token
     * @param expiresInSeconds Expiration in seconds
     */
    ExpiringToken(String token, int expiresInSeconds) {
        this.token = token;
        this.expiresInSeconds = expiresInSeconds;
    }

    /**
     * Gets the access token string.
     *
     * @return Token
     */
    public String getToken() {
        return token;
    }

    /**
     * Gets the token expiration time in seconds.
     *
     * @return Expiration in seconds
     */
    public int getExpiresInSeconds() {
        return expiresInSeconds;
    }
}
