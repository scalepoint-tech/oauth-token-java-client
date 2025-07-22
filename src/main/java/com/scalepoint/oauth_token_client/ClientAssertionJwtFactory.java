package com.scalepoint.oauth_token_client;

import io.jsonwebtoken.Jwts;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

class ClientAssertionJwtFactory {
    private final String tokenEndpointUri;
    private final String clientId;
    private final PrivateKey key;
    private final String thumbprint;

    public ClientAssertionJwtFactory(String tokenEndpointUri, String clientId, CertificateWithPrivateKey keyPair) {
        this.tokenEndpointUri = tokenEndpointUri;
        this.clientId = clientId;
        this.thumbprint = CertificateUtil.getThumbprint(keyPair.getCertificate());
        this.key = keyPair.getPrivateKey();
    }

    public String createAssertionToken() {
        Instant now = Instant.now();
        // no need to have a long-lived token (clock skew should be accounted for on the server-side)
        Instant expires = now.plusSeconds(10);

        return Jwts.builder()
                .header()
                    .type("JWT")
                    .add("x5t", thumbprint)
                    .keyId(thumbprint)
                    .and()
                .claims()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience().add(tokenEndpointUri).and()
                    .id(UUID.randomUUID().toString())
                    .issuedAt(Date.from(now))
                    .notBefore(Date.from(now))
                    .expiration(Date.from(expires))
                    .and()
                .signWith(key, Jwts.SIG.RS256)
                .compact();
    }

}
