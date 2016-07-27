package com.scalepoint.oauth_token_client;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class DigestUtil {
    static String sha1Hex(String data) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            digest.update(data.getBytes("utf8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        byte[] digestBytes = digest.digest();
        return DatatypeConverter.printHexBinary(digestBytes);
    }
}
