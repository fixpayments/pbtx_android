package com.pbtx.Model;

import pbtx.Pbtx;

public class KeyModel {

    Pbtx.PublicKey key;
    String alias;

    public Pbtx.PublicKey getKey() {
        return key;
    }

    public void setKey(Pbtx.PublicKey key) {
        this.key = key;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
