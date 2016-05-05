package com.scalepoint.oauth_token_client;

import org.apache.commons.codec.digest.DigestUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth2 "client_assertion" client credentials with "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" assertion type
 *
 * @see <a href="https://tools.ietf.org/html/rfc7521#section-6.2">Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication">OpenID Connect Core 1.0</a>
 */
@SuppressWarnings("WeakerAccess")
public class JwtBearerClientAssertionCredentials implements ClientCredentials {
    private final String credentialThumbprint;
    private final ClientAssertionJwtFactory assertionFactory;

    /**
     * Creates new JwtBearerClientAssertionCredentials
     *
     * @param tokenEndpointUri OAuth2 token endpoint URI. Used as "aud" claim value
     * @param clientId         OAuth2 "client_id"
     * @param keyPair          Certificate and private key. Certificate must be signed with SHA256. RSA keys must be 2048 bits long. Certificate must be associated with the client_id on the server.
     */
    @SuppressWarnings("SameParameterValue")
    public JwtBearerClientAssertionCredentials(String tokenEndpointUri, String clientId, CertificateWithPrivateKey keyPair) {
        this.assertionFactory = new ClientAssertionJwtFactory(tokenEndpointUri, clientId, keyPair);
        this.credentialThumbprint = DigestUtils.sha1Hex(
                tokenEndpointUri
                        + clientId
                        + CertificateUtil.getThumbprint(keyPair.getCertificate()));
    }

    @Override
    public List<NameValuePair> getPostParams() {
        String assertionToken = assertionFactory.CreateAssertionToken();
        ArrayList<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new NameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        params.add(new NameValuePair("client_assertion", assertionToken));
        return params;
    }

    @Override
    public String getCredentialThumbprint() {
        return credentialThumbprint;
    }
}
