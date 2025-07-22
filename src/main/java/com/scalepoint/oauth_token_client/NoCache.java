package com.scalepoint.oauth_token_client;

import java.io.IOException;

/**
 * No-cache token cache implementation
 */
@SuppressWarnings("unused")
public class NoCache implements TokenCache {
    /**
     * @param cacheKey         Cache key
     * @param underlyingSource Underlying token source to invoke
     * @return Token from underlying source
     * @throws IOException Exception from underlying source
     */
    @Override
    public String get(String cacheKey, TokenSource underlyingSource) throws IOException, InterruptedException {
        return underlyingSource.get().getToken();
    }
}
