package com.pbtx.Model;

import com.pbtx.PublicKey;

public class KeyModel {

    PublicKey key;
    String alias;

    public PublicKey getKey() {
        return key;
    }

    public void setKey(PublicKey key) {
        this.key = key;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
