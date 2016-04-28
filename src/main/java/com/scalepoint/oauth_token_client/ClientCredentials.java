package com.scalepoint.oauth_token_client;

import java.util.List;

/**
 * OAuth2 client credentials
 */
@SuppressWarnings("WeakerAccess")
public interface ClientCredentials {
    /**
     * Get client credentials token request parameters
     *
     * @return Token request parameters
     */
    List<NameValuePair> getPostParams();

    /**
     * Get client credentials thumbprint value
     *
     * @return Credential thumbprint
     */
    String getCredentialThumbprint();
}
