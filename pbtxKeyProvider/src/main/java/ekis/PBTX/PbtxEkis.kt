package ekis.PBTX

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import ekis.PBTX.Model.KeyModel
import ekis.PBTX.errors.AndroidKeyStoreDeleteError
import ekis.PBTX.errors.AndroidKeyStoreSigningError
import ekis.PBTX.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import ekis.PBTX.errors.ErrorString.Companion.GENERATE_KEY_ECGEN_MUST_USE_SECP256R1
import ekis.PBTX.errors.ErrorString.Companion.GENERATE_KEY_KEYGENSPEC_MUST_USE_EC
import ekis.PBTX.errors.ErrorString.Companion.GENERATE_KEY_MUST_HAS_PURPOSE_SIGN
import ekis.PBTX.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import ekis.PBTX.errors.InvalidKeyGenParameter
import ekis.PBTX.errors.QueryAndroidKeyStoreError
import ekis.PBTX.utils.PbtxUtils
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Utility class provides cryptographic methods to manage keys in the Android KeyStore Signature Provider and uses the keys to sign transactions.
 */
class PbtxEkis {

    companion object {
        const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val ANDROID_ECDSA_SIGNATURE_ALGORITHM: String = "SHA256withECDSA"
        private const val SECP256R1_CURVE_NAME = "secp256r1"

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
        private fun generateAndroidKeyStoreKey(
                keyGenParameterSpec: KeyGenParameterSpec,
                alias: String
        ): ByteArray {
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

            var mKey: ByteArray = PbtxUtils.getProtobufMessage(getKeystore(null), alias, null).key
            return mKey
        }

        /**
         * Generate a new key inside AndroidKeyStore by the given [alias] and return the new key in bye[] format
         *
         * The given [alias] is the identity of the key. The new key will be generated with the Default [KeyGenParameterSpec] from the [generateDefaultKeyGenParameterSpecBuilder]
         *
         * @param alias : Alias of the key store
         * @return Key : byte Array of generated public key
         */
        @JvmStatic
        fun createKey(alias: String): ByteArray {
            // Create a default KeyGenParameterSpec
            val keyGenParameterSpec: KeyGenParameterSpec =
                    generateDefaultKeyGenParameterSpecBuilder(alias).build()

            return generateAndroidKeyStoreKey(keyGenParameterSpec, alias)
        }


        /**
         * Get all (SECP256R1) keys in byte format from Android KeyStore
         * @return Array of public Keys with the alias.
         */

        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun listKeys(): ArrayList<KeyModel> {
            var mList: ArrayList<KeyModel> = ArrayList();

            try {
                val keyStore = getKeystore(null)
                var aliasList = keyStore.aliases().toList()
                aliasList.forEach() {
                    var keyModel = PbtxUtils.getProtobufMessage(keyStore, it, null)
                    mList.add(keyModel)

                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                throw QueryAndroidKeyStoreError(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR, ex)
            }

            return mList;
        }

        /**
         * Delete key in the Android KeyStore with matching alias name.
         *
         * @param alias : Alias name of the key needs to be deleted.
         */
        @Throws(AndroidKeyStoreDeleteError::class)
        @JvmStatic
        fun deleteKey(alias: String) {
            try {
                val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                    load(null)
                }
                ks.deleteEntry(alias)
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Loading the key store.
         */
        private fun getKeystore(loadStoreParameter: KeyStore.LoadStoreParameter?): KeyStore {
            return KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(loadStoreParameter) }
        }

        /**
         * Sign data with a key in the KeyStore.
         *
         * @param data ByteArray - data to be signed
         * @param alias String - identity of the key to be used for signing
         * @return Binary version of the signature
         * @throws AndroidKeyStoreSigningError
         */
        @Throws(AndroidKeyStoreSigningError::class)
        @JvmStatic
        fun signData(data: ByteArray, alias: String): ByteArray? {
            try {
                var keyStore = getKeystore(null)
                val keyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry

                return Signature.getInstance(ANDROID_ECDSA_SIGNATURE_ALGORITHM).run {
                    initSign(keyEntry.privateKey)
                    update(data)
                    sign()
                }

            } catch (ex: Exception) {
                throw AndroidKeyStoreSigningError(ex)
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
