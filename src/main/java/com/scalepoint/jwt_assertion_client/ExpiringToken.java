package com.scalepoint.jwt_assertion_client;

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
     * @return Token
     */
    public String getToken() {
        return token;
    }

    /**
     * @return Expiration in seconds
     */
    public int getExpiresInSeconds() {
        return expiresInSeconds;
    }
}
