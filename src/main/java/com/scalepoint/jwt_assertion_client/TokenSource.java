package com.scalepoint.jwt_assertion_client;

import java.io.IOException;

/**
 * Represents function returning token
 */
interface TokenSource {
    /**
     * @return Token
     * @throws IOException
     */
    ExpiringToken get() throws IOException;
}
