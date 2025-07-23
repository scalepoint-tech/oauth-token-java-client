package com.scalepoint.oauth_token_client;

import java.io.IOException;

/**
 * Read-through cache for access tokens
 */
public interface TokenCache {
    /**
     * Gets a token from the cache or retrieves it from the underlying source if not cached.
     *
     * @param cacheKey         Cache key
     * @param underlyingSource Underlying token source to invoke on cache miss
     * @return Token from either cache or underlying source
     * @throws IOException Exception from underlying cache
     * @throws InterruptedException if the thread is interrupted during token retrieval
     */
    String get(String cacheKey, TokenSource underlyingSource) throws IOException, InterruptedException;
}
