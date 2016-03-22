package com.scalepoint.jwt_assertion_client;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Properties;

class TestCertificateHelper {

    public static RSACertificateWithPrivateKey load() {
        try {
            Properties config = new Properties();
            config.load(new FileInputStream("config.properties"));
            return getKeyPair(config.getProperty("keyStoreFileName"), config.getProperty("keyStorePassword"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static RSACertificateWithPrivateKey getKeyPair(String keyStoreFileName, String keyStorePassword) throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); // or KeyStore.getInstance("pkcs12", "SunJSSE") to load .pfx
        keyStore.load(new FileInputStream(keyStoreFileName), null);
        String a = keyStore.aliases().nextElement();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(a, keyStorePassword.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(a);
        return new RSACertificateWithPrivateKey(privateKey, certificate);
    }
}
