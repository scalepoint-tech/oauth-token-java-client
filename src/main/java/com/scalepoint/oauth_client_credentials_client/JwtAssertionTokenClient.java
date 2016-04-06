package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.fluent.Form;

import java.io.IOException;
import java.util.List;

/**
 * OAuth2 Token endpoint client with client_credentials flow support using "private_key_jwt" client authentication scheme.
 * Tokens are cached in-memory by default.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7521#section-6.2">Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID Connect Core 1.0</a>
 */
public class JwtAssertionTokenClient implements TokenClient {

    private final JwtAssertionFactory assertionFactory;
    private final InternalTokenClient internalTokenClient;
    private final String clientId;
    private final String partialCacheKey;
    private final TokenCache cache;

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri OAuth2 Token endpoint URI
     * @param clientId         OAuth2 "client_id"
     * @param keyPair          Certificate and private key. Certificate must be signed with SHA256. RSA keys must be 2048 bits long. Certificate must be associated with the client_id on the server.
     */
    @SuppressWarnings({"SameParameterValue", "unused"})
    public JwtAssertionTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair) {
        this(tokenEndpointUri, clientId, keyPair, LazyCacheHolder.CACHE);
    }

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri OAuth2 Token endpoint URI
     * @param clientId         OAuth2 "client_id"
     * @param keyPair          Certificate and private key. Certificate must be signed with SHA256. RSA keys must be 2048 bits long. Certificate must be associated with the client_id on the server.
     * @param cache            Token cache
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue", "unused"})
    public JwtAssertionTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair, TokenCache cache) {
        this.assertionFactory = new JwtAssertionFactory(tokenEndpointUri, clientId, keyPair);
        this.internalTokenClient = new InternalTokenClient(tokenEndpointUri);
        this.clientId = clientId;
        this.partialCacheKey = StringUtils.join(tokenEndpointUri, clientId, CertificateUtil.getThumbprint(keyPair.getCertificate()), "|");
        this.cache = cache;
    }

    /**
     * Retrieve access token for the configured "client_id" and specified scopes. Request to the server is only performed if matching valid token is not in the cache
     *
     * @param scopes One or more OAuth2 scopes to request
     * @return Access token
     * @throws IOException Exception during token endpoint communication
     */
    @Override
    public String getToken(final String... scopes) throws IOException {
        if (scopes == null || scopes.length < 1) {
            throw new IllegalArgumentException("At least one scope must be present");
        }
        final String scopeString = StringUtils.join(scopes, " ");
        final String cacheKey = StringUtils.join(partialCacheKey, scopeString, ":");
        return cache.get(cacheKey, new TokenSource() {
            @Override
            public ExpiringToken get() throws IOException {
                String assertionToken = assertionFactory.CreateAssertionToken();

                final List<NameValuePair> params = Form.form()
                        .add("grant_type", "client_credentials")
                        .add("client_id", clientId)
                        .add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        .add("client_assertion", assertionToken)
                        .add("scope", StringUtils.join(scopes, " "))
                        .build();
                return internalTokenClient.getToken(params);
            }
        });
    }
}
