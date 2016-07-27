package com.scalepoint.oauth_token_client;

class StringUtil {
    static String join(String[] strings, String separator) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < strings.length; i++) {
            if (i > 0)
                builder.append(separator);
            builder.append(strings[i]);
        }
        return builder.toString();
    }
}
