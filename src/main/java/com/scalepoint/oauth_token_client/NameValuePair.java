package com.scalepoint.oauth_token_client;

/**
 * Name value pair
 */
@SuppressWarnings("WeakerAccess")
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

    @Override
    public boolean equals(Object object) {
        if(this == object) {
            return true;
        } else if(!(object instanceof NameValuePair)) {
            return false;
        } else {
            NameValuePair that = (NameValuePair)object;
            return this.name.equals(that.name) && this.value.equals(that.value);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + name.hashCode();
        result = prime * result + value.hashCode();
        return result;
    }
}
