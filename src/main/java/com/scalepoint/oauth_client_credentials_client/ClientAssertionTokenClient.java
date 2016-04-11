package com.scalepoint.oauth_client_credentials_client;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 Token endpoint client with client_credentials flow support using "private_key_jwt" client authentication scheme.
 * Tokens are cached in-memory by default.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7521#section-6.2">Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID Connect Core 1.0</a>
 */
public class ClientAssertionTokenClient extends CustomGrantTokenClient {

    private final ClientAssertionJwtFactory assertionFactory;

    /**
     * OAuth2 Creates new token client
     *
     * @param tokenEndpointUri OAuth2 Token endpoint URI
     * @param clientId         OAuth2 "client_id"
     * @param keyPair          Certificate and private key. Certificate must be signed with SHA256. RSA keys must be 2048 bits long. Certificate must be associated with the client_id on the server.
     */
    @SuppressWarnings({"SameParameterValue", "unused"})
    public ClientAssertionTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair) {
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
    public ClientAssertionTokenClient(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair, TokenCache cache) {
        super(tokenEndpointUri,
                StringUtils.join(tokenEndpointUri, clientId, CertificateUtil.getThumbprint(keyPair.getCertificate()), "|"),
                cache);

        this.assertionFactory = new ClientAssertionJwtFactory(tokenEndpointUri, clientId, keyPair);
    }

    @Override
    protected List<NameValuePair> getPostParams() {
        String assertionToken = assertionFactory.CreateAssertionToken();
        ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new NameValuePair("grant_type", "client_credentials"));
        params.add(new NameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        params.add(new NameValuePair("client_assertion", assertionToken));
        return params;
    }

}
