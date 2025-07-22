package com.scalepoint.oauth_token_client;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

final class CertificateUtil {
    static String getThumbprint(Certificate certificate) {
        byte[] der;
        try {
            der = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        md.update(der);
        byte[] digest = md.digest();
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    static Boolean checkIfMatch(PrivateKey privateKey, X509Certificate certificate) {
        // Currently, only RSA validation is supported
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        return rsaPublicKey.getModulus().equals(rsaPrivateKey.getModulus())
                && BigInteger.valueOf(2)
                .modPow(
                        rsaPublicKey.getPublicExponent()
                                .multiply(rsaPrivateKey.getPrivateExponent())
                                .subtract(BigInteger.ONE),
                        rsaPublicKey.getModulus())
                .equals(BigInteger.ONE);
    }
}
