package com.scalepoint.oauth_client_credentials_client;

final class LazyCacheHolder {
    public static final TokenCache CACHE = new InMemoryTokenCache();
}
