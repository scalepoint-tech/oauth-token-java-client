package com.scalepoint.oauth_client_credentials_client;

import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

class ClientAssertionJwtFactory {
    private final String tokenEndpointUri;
    private final String clientId;
    private final Key key;
    private final String thumbprint;

    public ClientAssertionJwtFactory(String tokenEndpointUri, String clientId, RSACertificateWithPrivateKey keyPair) {
        this.tokenEndpointUri = tokenEndpointUri;
        this.clientId = clientId;
        this.thumbprint = CertificateUtil.getThumbprint(keyPair.getCertificate());
        this.key = keyPair.getPrivateKey();
    }

    public String CreateAssertionToken() {
        Date now = new Date();
        Date expires = new Date(now.getTime() + 10000 /* 10 seconds */);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam(JwsHeader.X509_CERT_SHA1_THUMBPRINT, thumbprint)
                .setIssuer(clientId)
                .setSubject(clientId)
                .setAudience(tokenEndpointUri)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setNotBefore(now)
                .setExpiration(expires)
                .signWith(SignatureAlgorithm.RS256, key)
                .compact();
    }

}
