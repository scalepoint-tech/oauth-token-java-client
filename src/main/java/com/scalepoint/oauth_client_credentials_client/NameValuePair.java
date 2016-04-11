package com.scalepoint.oauth_client_credentials_client;

/**
 * Name value pair
 */
public class NameValuePair {
    final String name;
    final String value;

    /**
     * @param name Name
     * @param value Value
     */
    public NameValuePair(String name, String value) {
        this.name = name;
        this.value = value;
    }

    /**
     * @return Name
     */
    String getName() {
        return name;
    }

    /**
     * @return Value
     */
    String getValue() {
        return value;
    }
}
