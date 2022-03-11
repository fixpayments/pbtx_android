package ekis.PBTX.utils

import com.google.crypto.tink.subtle.EllipticCurves
import ekis.PBTX.Model.KeyModel
import java.security.KeyFactory
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

class PbtxUtils {

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
        fun getProtobufMessage(
                keyStore: KeyStore,
                alias: String,
                password: KeyStore.ProtectionParameter?
        ): KeyModel {
            val keyEntry = keyStore.getEntry(alias, password) as KeyStore.PrivateKeyEntry
            val ecPublicKey =
                    KeyFactory.getInstance(keyEntry.certificate.publicKey.algorithm).generatePublic(
                            X509EncodedKeySpec(keyEntry.certificate.publicKey.encoded)
                    ) as ECPublicKey

            val bytes = EllipticCurves.pointEncode(
                    EllipticCurves.CurveType.NIST_P256,
                    EllipticCurves.PointFormatType.COMPRESSED,
                    ecPublicKey.w
            )

            val i = 1
            val b = i.toByte()
            val ba = ByteArray(1)
            ba[0] = b
            // create a destination array that is the size of the two arrays
            val destination = ByteArray(bytes.size + ba.size)

            System.arraycopy(ba, 0, destination, 0, 1)
            System.arraycopy(bytes, 0, destination, 1, bytes.size)

            return protobufKeyModel(destination, alias)
        }

        /**
         * Wrapping the byte[] in [KeyModel] Object.
         */
        private fun protobufKeyModel(key: ByteArray, alias: String): KeyModel {

            var keyModel = KeyModel();
            keyModel.alias = alias
            keyModel.key = key

            return keyModel

        }

    }
}