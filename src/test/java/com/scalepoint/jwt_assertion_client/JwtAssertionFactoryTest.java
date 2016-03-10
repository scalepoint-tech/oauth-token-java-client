package com.scalepoint.jwt_assertion_client;

import io.jsonwebtoken.*;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Validate that assertion token is generated according to the specification
 */
public class JwtAssertionFactoryTest {

    private final static String TOKEN_ENDPOINT_URI = "https://foobar";
    private final static String CLIENT_ID = "clientid";
    private Jws<Claims> token;
    private String thumbprint;

    @BeforeTest
    public void init() {
        RSACertificateWithPrivateKey keyPair = TestCertificateHelper.load();
        thumbprint = CertificateUtil.getThumbprint(keyPair.getCertificate());
        JwtAssertionFactory factory = new JwtAssertionFactory(TOKEN_ENDPOINT_URI, CLIENT_ID, keyPair);
        String tokenString = factory.CreateAssertionToken();
        token = Jwts.parser().setSigningKey(keyPair.getPrivateKey()).parseClaimsJws(tokenString);
    }

    @Test
    public void shouldBeJwt() {
        Assert.assertEquals(token.getHeader().getType(), "JWT");
    }

    @Test
    public void shouldUseRS256() {
        Assert.assertEquals(token.getHeader().getAlgorithm(), "RS256");
    }

    @Test
    public void shouldContainX5t() {
        Assert.assertEquals(token.getHeader().get("x5t"), thumbprint);
    }

    @Test
    public void shouldContainValidIssuer() {
        Assert.assertEquals(token.getBody().getIssuer(), CLIENT_ID);
    }

    @Test
    public void shouldContainValidSubject() {
        Assert.assertEquals(token.getBody().getSubject(), CLIENT_ID);
    }

    @Test
    public void shouldContainValidAudience() {
        Assert.assertEquals(token.getBody().getAudience(), TOKEN_ENDPOINT_URI);
    }

    @Test
    public void shouldContainJwtId() {
        Assert.assertNotNull(token.getBody().getId());
    }

    @Test
    public void shouldContainExpiration() {
        Assert.assertNotNull(token.getBody().getExpiration());
    }

    @Test
    public void shouldContainIssuedAt() {
        Assert.assertNotNull(token.getBody().getIssuedAt());
    }
}
