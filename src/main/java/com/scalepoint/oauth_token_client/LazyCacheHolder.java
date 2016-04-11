package com.scalepoint.oauth_token_client;

final class LazyCacheHolder {
    public static final TokenCache CACHE = new InMemoryTokenCache();
}
