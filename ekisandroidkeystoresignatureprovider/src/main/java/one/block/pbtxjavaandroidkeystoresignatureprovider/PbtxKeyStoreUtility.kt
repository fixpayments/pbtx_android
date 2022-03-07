package one.block.pbtxjavaandroidkeystoresignatureprovider

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.google.crypto.tink.subtle.EllipticCurves
import com.google.protobuf.ByteString
import com.google.protobuf.TextFormat
import one.block.pbtxjavaandroidkeystoresignatureprovider.errors.*
import one.block.pbtxjavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import one.block.pbtxjavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.GENERATE_KEY_ECGEN_MUST_USE_SECP256R1
import one.block.pbtxjavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.GENERATE_KEY_KEYGENSPEC_MUST_USE_EC
import one.block.pbtxjavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.GENERATE_KEY_MUST_HAS_PURPOSE_SIGN
import one.block.pbtxjavaandroidkeystoresignatureprovider.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import pbtx.Pbtx
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec


/**
 * Utility class provides cryptographic methods to manage keys in the Android KeyStore Signature Provider and uses the keys to sign transactions.
 */
class PbtxKeyStoreUtility {

    companion object {
        private const val ANDROID_PUBLIC_KEY_OID_ID: Int = 0
        private const val EC_PUBLICKEY_OID_INDEX: Int = 0
        private const val SECP256R1_OID_INDEX: Int = 1
        private const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val ANDROID_ECDSA_SIGNATURE_ALGORITHM: String = "SHA256withECDSA"
        private const val ANDROID_RSA_SIGNATURE_ALGORITHM: String = "SHA256withRSA"
        private const val SECP256R1_CURVE_NAME = "secp256r1"
        private const val PEM_OBJECT_TYPE_PUBLIC_KEY = "PUBLIC KEY"
        private var password: KeyStore.ProtectionParameter? = null


        /**
         * Generate a new key inside Android KeyStore by the given [keyGenParameterSpec] and return the new key in EOS format
         *
         * The given [keyGenParameterSpec] is the parameter specification to generate a new key. This specification
         * must include the following information if the key to be generated needs to be EOS Mainnet compliant:
         *
         * - [KeyGenParameterSpec] must include [KeyProperties.PURPOSE_SIGN]
         * - [KeyGenParameterSpec.getAlgorithmParameterSpec] must be of type [ECGenParameterSpec]
         * - [KeyGenParameterSpec.getAlgorithmParameterSpec]'s curve name must be [SECP256R1_CURVE_NAME]
         */
        @JvmStatic
        fun generateAndroidKeyStoreKey(keyGenParameterSpec: KeyGenParameterSpec) {
            // Parameter Spec must include PURPOSE_SIGN
            if (KeyProperties.PURPOSE_SIGN and keyGenParameterSpec.purposes != KeyProperties.PURPOSE_SIGN) {
                throw InvalidKeyGenParameter(GENERATE_KEY_MUST_HAS_PURPOSE_SIGN)
            }

            // Parameter Spec's algorithm spec must be of type ECGenParameterSpec
            if (keyGenParameterSpec.algorithmParameterSpec !is ECGenParameterSpec) {
                throw InvalidKeyGenParameter(GENERATE_KEY_KEYGENSPEC_MUST_USE_EC)
            }

            // The curve of Parameter Spec's algorithm must be SECP256R1
            if ((keyGenParameterSpec.algorithmParameterSpec as ECGenParameterSpec).name != SECP256R1_CURVE_NAME) {
                throw InvalidKeyGenParameter(GENERATE_KEY_ECGEN_MUST_USE_SECP256R1)
            }

            val kpg: KeyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            kpg.initialize(keyGenParameterSpec)
            kpg.generateKeyPair()

        }

        /**
         * Generate a new key inside AndroidKeyStore by the given [alias] and return the new key in EOS format
         *
         * The given [alias] is the identity of the key. The new key will be generated with the Default [KeyGenParameterSpec] from the [generateDefaultKeyGenParameterSpecBuilder]
         */
        @JvmStatic
        fun generateAndroidKeyStoreKey(alias: String) {
            // Create a default KeyGenParameterSpec
            val keyGenParameterSpec: KeyGenParameterSpec =
                this.generateDefaultKeyGenParameterSpecBuilder(alias).build()

            generateAndroidKeyStoreKey(keyGenParameterSpec)
        }


        /**
         * Get all (SECP256R1) keys in EOS format from Android KeyStore
         * @param alias String - the key's identity
         * @param password KeyStore.ProtectionParameter? - the password to load all the keys
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         * @return String - the SECP256R1 key in the Android KeyStore
         */
        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun generateProtoMessage(
            alias: String,
            password: KeyStore.ProtectionParameter?,
            loadStoreParameter: KeyStore.LoadStoreParameter?
        ) {
            try {
                val keyStore =
                    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(loadStoreParameter) }
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

                var ubit: UByteArray = destination.toUByteArray()
                var uakey: String = ""
                ubit.forEach {
                    uakey += it
                    uakey += ","
                }

                Log.d("ProtoMessageUakey~>", "$uakey")
                protobufTrial(destination)

                var signMsg = sign(
                    "0102030405060708090a0b0c0d0e0f".toByteArray(),
                    keyEntry
                )
                if (signMsg != null) {
                    Log.d("ProtoMessageSign~>", "${signMsg.toHexString()}")
                }

            } catch (ex: Exception) {
                ex.printStackTrace()
                throw QueryAndroidKeyStoreError(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        fun ByteArray.toHexString(): String {
            return this.joinToString("") {
                java.lang.String.format("%02x", it)
            }
        }


        /**
         * Sign data with a key in the KeyStore.
         *
         * @param data ByteArray - data to be signed
         * @param alias String - identity of the key to be used for signing
         * @param password KeyStore.ProtectionParameter - password of the key
         * @return Binary version of the signature
         * @throws AndroidKeyStoreSigningError
         */
        @Throws(AndroidKeyStoreSigningError::class)
        @JvmStatic
        fun sign(
            data: ByteArray,
            privateKey: KeyStore.PrivateKeyEntry
        ): ByteArray? {
            try {
                return Signature.getInstance(ANDROID_ECDSA_SIGNATURE_ALGORITHM).run {
                    initSign(privateKey.privateKey)
                    update(data)
                    sign()
                }

            } catch (ex: Exception) {
                throw AndroidKeyStoreSigningError(ex)
            }
        }

        /**
         * Delete a key inside Android KeyStore by its alias
         *
         * @param keyAliasToDelete String - the alias of the key to delete
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         * @throws AndroidKeyStoreDeleteError
         */
        @Throws(AndroidKeyStoreDeleteError::class)
        @JvmStatic
        fun deleteKeyByAlias(
            keyAliasToDelete: String,
            loadStoreParameter: KeyStore.LoadStoreParameter?
        ): Boolean {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }
                ks.deleteEntry(keyAliasToDelete)
                // If the key still exists, return false. Otherwise, return true
                return !ks.containsAlias(keyAliasToDelete)
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }


        fun protobufTrial(key: ByteArray) {

            var s: String = ""
            key.forEach {
                s += it
            }
//            val s: String = "PUB_R1_4ucLsQSE3KXMqDDt1kUQodBKwLrwE8arGvWvitdxSv9n8ej2y7"
            val bs = TextFormat.unescapeBytes(s)

            val byteString = ByteString.copyFrom(key);

            val key1 = Pbtx.PublicKey.newBuilder()
                .setKeyBytes(byteString)
                .setType(Pbtx.KeyType.EKIS_KEY)
                .build()

            Log.d("ProtoMessages>", key1.toByteArray().toHexString())
            Log.d("ProtoMessages>", key1.serializedSize.toString())

//            val keyWeight = Pbtx.KeyWeight.newBuilder()
//                .setKey(key1)
//                .setWeight(1)
//                .build()
//            val message = Pbtx.Permission.newBuilder()
//                .setActor(3)
//                .setThreshold(2)
//                .addAllKeys(listOf(keyWeight))
//                .build()
//            val bytes = message.toByteArray()
//            Log.d("~~>",Hex.encode(bytes))
        }


        /**
         * Delete all keys in the Android KeyStore
         *
         * @param loadStoreParameter KeyStore.LoadStoreParameter? - the KeyStore Parameter to load the KeyStore instance
         */

        @Throws(AndroidKeyStoreDeleteError::class)
        @JvmStatic
        fun deleteAllKeys(loadStoreParameter: KeyStore.LoadStoreParameter?) {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(loadStoreParameter)
                }

                ks.aliases().toList().forEach { ks.deleteEntry(it) }
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Generate a default [KeyGenParameterSpec.Builder] with
         *
         * [KeyProperties.DIGEST_SHA256] as its digest
         *
         * [ECGenParameterSpec] as its algorithm parameter spec
         *
         * [SECP256R1_CURVE_NAME] as its EC curve
         *
         * @return KeyGenParameterSpec
         */
        @JvmStatic
        private fun generateDefaultKeyGenParameterSpecBuilder(alias: String): KeyGenParameterSpec.Builder {
            return KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec(SECP256R1_CURVE_NAME))
        }
    }
}