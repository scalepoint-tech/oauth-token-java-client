package com.scalepoint.oauth_token_client;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

/**
 * Container for RSA private key and its matching X509 certificate
 */
public class RSACertificateWithPrivateKey {
    private X509Certificate certificate;
    private RSAPrivateKey privateKey;

    /**
     * Create new container for private key and certificate
     *
     * @param privateKey  Private key
     * @param certificate X509 certificate
     */
    public RSACertificateWithPrivateKey(RSAPrivateKey privateKey, X509Certificate certificate) {

        if (!CertificateUtil.checkIfMatch(privateKey, certificate)) {
            throw new IllegalArgumentException("Certificate does not match private key");
        }

        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    /**
     * @return Certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * @return Private key
     */
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }
}
