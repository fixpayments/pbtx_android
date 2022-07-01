package com.pbtx.utils

import com.google.protobuf.ByteString
import com.pbtx.model.KeyModel
import pbtx.KeyType
import pbtx.PublicKey
import java.security.KeyStore

class ProtobufProvider {

    companion object {

        /**
         * Generating the protobuf message from the public key
         *
         * @param [KeyStore] : Keystore of the android.
         * @param alias : Alias of the key for which needs to generate a protobyf message
         * @param password : password of the alias
         *
         * @return KeyModel : byte[] of the protobuf message.
         *
         */
        fun getProtobufModels(keyStore: KeyStore, alias: String, password: KeyStore.ProtectionParameter?): KeyModel {
            val keyEntry = keyStore.getEntry(alias, password) as KeyStore.PrivateKeyEntry
            val compressedPublicKey = KeyStoreProvider.getCompressedPublicKey(keyEntry)

            val publicKey = createPublicKeyProtoMessage(PbtxUtils.additionByteAdd(compressedPublicKey))
            return KeyModel(publicKey, alias)
        }

        /**
         * Creating a protobuf message of compressed public key.
         *
         * @param key Public key from the keystore
         * @return Protobuf message of the compressed public key
         *
         */
        fun createPublicKeyProtoMessage(key: ByteArray): PublicKey {
            val byteString = ByteString.copyFrom(key)
            return PublicKey.newBuilder()
                .setKeyBytes(byteString)
                .setType(KeyType.EOSIO_KEY)
                .build()
        }
    }

}