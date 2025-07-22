package com.scalepoint.oauth_token_client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Validate that assertion token is generated according to the specification
 */
public class ClientAssertionJwtFactoryTest {

    private final static String TOKEN_ENDPOINT_URI = "https://foobar";
    private final static String CLIENT_ID = "clientid";
    private Jws<Claims> token;
    private String thumbprint;

    @BeforeClass
    public void init() {
        CertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        thumbprint = CertificateUtil.getThumbprint(keyPair.getCertificate());
        ClientAssertionJwtFactory factory = new ClientAssertionJwtFactory(TOKEN_ENDPOINT_URI, CLIENT_ID, keyPair);
        String tokenString = factory.createAssertionToken();
        // Use the PUBLIC key from the certificate to verify the JWT signature, not the private key
        token = Jwts.parser().verifyWith(keyPair.getCertificate().getPublicKey()).build().parseSignedClaims(tokenString);
    }

    @Test
    public void testIsJwt() {
        Assert.assertEquals(token.getHeader().getType(), "JWT");
    }

    @Test
    public void testUsesRS256() {
        Assert.assertEquals(token.getHeader().getAlgorithm(), "RS256");
    }

    @Test
    public void testContainsX5t() {
        Assert.assertEquals(token.getHeader().get("x5t"), thumbprint);
    }

    @Test
    public void testContainsValidIssuer() {
        Assert.assertEquals(token.getPayload().getIssuer(), CLIENT_ID);
    }

    @Test
    public void testContainsValidSubject() {
        Assert.assertEquals(token.getPayload().getSubject(), CLIENT_ID);
    }

    @Test
    public void testContainsValidAudience() {
        // In newer JJWT versions, audience is returned as a Set<String>
        Assert.assertTrue(token.getPayload().getAudience().contains(TOKEN_ENDPOINT_URI));
    }

    @Test
    public void testContainsJwtId() {
        Assert.assertNotNull(token.getPayload().getId());
    }

    @Test
    public void testContainsExpiration() {
        Assert.assertNotNull(token.getPayload().getExpiration());
    }

    @Test
    public void testContainsIssuedAt() {
        Assert.assertNotNull(token.getPayload().getIssuedAt());
    }
}
