package com.scalepoint.oauth_token_client;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Simple in-memory token cache implementation using ConcurrentHashMap
 */
public class InMemoryTokenCache implements TokenCache {
    private final ConcurrentMap<String, CachedToken> cache = new ConcurrentHashMap<>();

    /**
     * Wrapper class to store token with its expiration time
     */
    private static class CachedToken {
        private final String token;
        private final Instant expirationTime;

        CachedToken(String token, long expiresInSeconds) {
            this.token = token;
            this.expirationTime = Instant.now().plusSeconds(expiresInSeconds);
        }

        String getToken() {
            return token;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expirationTime);
        }
    }

    /**
     * @param cacheKey         Cache key
     * @param underlyingSource Underlying token source to invoke on cache miss
     * @return Token from either cache or underlying source
     * @throws IOException Exception from underlying source
     */
    @Override
    public String get(String cacheKey, TokenSource underlyingSource) throws IOException, InterruptedException {
        CachedToken cachedToken = cache.get(cacheKey);
        
        // Check if we have a valid (non-expired) token
        if (cachedToken != null && !cachedToken.isExpired()) {
            return cachedToken.getToken();
        }
        
        // Token is missing or expired - fetch a new one
        ExpiringToken token = underlyingSource.get();
        if (token.getExpiresInSeconds() <= 0) {
            throw new IllegalArgumentException("Authorization server does not provide token expiration information. Consider using NoCache or custom cache implementation to avoid performance penalty caused by locking.");
        }
        
        // Use compute for thread-safe update, but we already have the token
        CachedToken newToken = new CachedToken(token.getToken(), token.getExpiresInSeconds());
        cache.compute(cacheKey, (key, existingToken) -> {
            // Double-check: another thread might have updated it with a fresh token
            if (existingToken != null && !existingToken.isExpired()) {
                return existingToken;
            }
            return newToken;
        });
        
        return newToken.getToken();
    }
}
