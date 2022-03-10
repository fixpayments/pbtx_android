package ekis.pbtxjavaandroidkeystoresignatureprovider.Model;

import com.google.protobuf.Message;

import java.util.ArrayList;

public class KeyModel {

    byte[] key;
    String alias;

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
