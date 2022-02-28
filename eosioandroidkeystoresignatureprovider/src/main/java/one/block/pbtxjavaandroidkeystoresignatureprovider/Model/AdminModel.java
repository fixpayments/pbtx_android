package one.block.pbtxjavaandroidkeystoresignatureprovider.Model;

import com.google.protobuf.Message;

import java.util.ArrayList;

public class AdminModel extends
        com.google.protobuf.GeneratedMessage implements com.google.protobuf.MessageOrBuilder{
    public static void registerAllExtensions(
            com.google.protobuf.ExtensionRegistry registry) {
    }

    private AdminModel(Builder builder) {
        super(builder);
    }

    int actor;
    int threshold;
    ArrayList<KeyModel> arrayList = new ArrayList<>();

    public int getActor() {
        return actor;
    }

    public void setActor(int actor) {
        this.actor = actor;
    }

    public int getThreshold() {
        return threshold;
    }

    public void setThreshold(int threshold) {
        this.threshold = threshold;
    }

    @Override
    protected FieldAccessorTable internalGetFieldAccessorTable() {
        return null;
    }

    @Override
    protected Message.Builder newBuilderForType(BuilderParent parent) {
        return null;
    }

    @Override
    public Message.Builder newBuilderForType() {
        return null;
    }

    @Override
    public Message.Builder toBuilder() {
        return null;
    }

    @Override
    public Message getDefaultInstanceForType() {
        return null;
    }


    private class KeyModel {

        String key;
        int weight;

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public int getWeight() {
            return weight;
        }

        public void setWeight(int weight) {
            this.weight = weight;
        }
    }

}
