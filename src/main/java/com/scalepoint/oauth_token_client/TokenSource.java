package com.scalepoint.oauth_token_client;

import java.io.IOException;

/**
 * Represents function returning token
 */
public interface TokenSource {
    /**
     * Gets an expiring token.
     *
     * @return Token
     * @throws IOException if an I/O error occurs during token retrieval
     * @throws InterruptedException if the thread is interrupted during token retrieval
     */
    ExpiringToken get() throws IOException, InterruptedException;
}
