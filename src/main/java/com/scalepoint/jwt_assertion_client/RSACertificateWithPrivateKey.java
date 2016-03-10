package com.scalepoint.jwt_assertion_client;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Container for RSA private key and its matching X509 certificate
 */
public class RSACertificateWithPrivateKey {
    private X509Certificate certificate;
    private RSAPrivateKey privateKey;

    /**
     * Create new container for private key and certificate
     * @param privateKey Private key
     * @param certificate X509 certificate
     */
    public RSACertificateWithPrivateKey(RSAPrivateKey privateKey, X509Certificate certificate) {

        ValidateIfMatch(privateKey, certificate);

        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    private void ValidateIfMatch(RSAPrivateKey privateKey, X509Certificate certificate) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        Boolean match = rsaPublicKey.getModulus().equals(privateKey.getModulus())
                        && BigInteger.valueOf(2)
                            .modPow(
                                    rsaPublicKey.getPublicExponent()
                                        .multiply(privateKey.getPrivateExponent())
                                        .subtract(BigInteger.ONE),
                                    rsaPublicKey.getModulus())
                            .equals( BigInteger.ONE );

        if (!match) {
            throw new IllegalArgumentException("Certificate does not match private key");
        }
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
