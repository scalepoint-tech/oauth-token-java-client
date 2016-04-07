package com.scalepoint.oauth_client_credentials_client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Validate that assertion token is generated according to the specification
 */
@SuppressWarnings("unused")
public class ClientAssertionJwtFactoryTest {

    private final static String TOKEN_ENDPOINT_URI = "https://foobar";
    private final static String CLIENT_ID = "clientid";
    private Jws<Claims> token;
    private String thumbprint;

    @BeforeClass
    public void init() {
        RSACertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        thumbprint = CertificateUtil.getThumbprint(keyPair.getCertificate());
        ClientAssertionJwtFactory factory = new ClientAssertionJwtFactory(TOKEN_ENDPOINT_URI, CLIENT_ID, keyPair);
        String tokenString = factory.CreateAssertionToken();
        token = Jwts.parser().setSigningKey(keyPair.getPrivateKey()).parseClaimsJws(tokenString);
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
        Assert.assertEquals(token.getBody().getIssuer(), CLIENT_ID);
    }

    @Test
    public void testContainsValidSubject() {
        Assert.assertEquals(token.getBody().getSubject(), CLIENT_ID);
    }

    @Test
    public void testContainsValidAudience() {
        Assert.assertEquals(token.getBody().getAudience(), TOKEN_ENDPOINT_URI);
    }

    @Test
    public void testContainsJwtId() {
        Assert.assertNotNull(token.getBody().getId());
    }

    @Test
    public void testContainsExpiration() {
        Assert.assertNotNull(token.getBody().getExpiration());
    }

    @Test
    public void testContainsIssuedAt() {
        Assert.assertNotNull(token.getBody().getIssuedAt());
    }
}
