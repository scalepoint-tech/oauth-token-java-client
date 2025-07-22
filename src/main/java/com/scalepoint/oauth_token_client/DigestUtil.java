package com.scalepoint.oauth_token_client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

class DigestUtil {
    static String sha1Hex(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] digestBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digestBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
