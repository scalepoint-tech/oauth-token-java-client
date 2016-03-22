package com.scalepoint.jwt_assertion_client;

import io.jsonwebtoken.impl.Base64UrlCodec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

class CertificateUtil {
    public static String getThumbprint(Certificate certificate) {
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
        return new Base64UrlCodec().encode(digest);
    }

    public static Boolean checkIfMatch(RSAPrivateKey privateKey, X509Certificate certificate) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();

        return rsaPublicKey.getModulus().equals(privateKey.getModulus())
                && BigInteger.valueOf(2)
                .modPow(
                        rsaPublicKey.getPublicExponent()
                                .multiply(privateKey.getPrivateExponent())
                                .subtract(BigInteger.ONE),
                        rsaPublicKey.getModulus())
                .equals(BigInteger.ONE);
    }
}
