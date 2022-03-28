package com.pbtx.utils

import com.google.protobuf.ByteString
import com.pbtx.Model.KeyModel
import pbtx.Pbtx
import java.security.KeyStore

class ProtoBufProvider {

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
        fun getProtobufModels(
                keyStore: KeyStore,
                alias: String,
                password: KeyStore.ProtectionParameter?
        ): KeyModel {
            val keyEntry = keyStore.getEntry(alias, password) as KeyStore.PrivateKeyEntry

            var compressedPublicKey = KeyStoreProvider.getCompressedPublicKey(keyEntry)

            return protobufKeyModel(createPublicKeyProtoMessage(PbtxUtils.additionByteAdd(compressedPublicKey)), alias)
        }

        /**
         * Wrapping the byte[] in [KeyModel] Object.
         */
        private fun protobufKeyModel(key: Pbtx.PublicKey, alias: String): KeyModel {

            var keyModel = KeyModel();
            keyModel.alias = alias
            keyModel.key = key

            return keyModel

        }

        /**
         * Creating a protobuf message of compressed public key.
         *
         * @param key Public key from the keystore
         * @return Protobuf message of the compressed public key
         *
         */
        fun createPublicKeyProtoMessage(key: ByteArray): Pbtx.PublicKey {

            val byteString = ByteString.copyFrom(key);

            val protoBufMessage = Pbtx.PublicKey.newBuilder()
                    .setKeyBytes(byteString)
                    .setType(Pbtx.KeyType.EOSIO_KEY)
                    .build()

            return protoBufMessage
        }
    }

}