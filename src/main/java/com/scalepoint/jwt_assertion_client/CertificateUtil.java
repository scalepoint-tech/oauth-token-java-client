package com.scalepoint.jwt_assertion_client;

import io.jsonwebtoken.impl.Base64UrlCodec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

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
}
