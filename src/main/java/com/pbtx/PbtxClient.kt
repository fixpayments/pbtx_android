package com.pbtx

import android.security.keystore.KeyGenParameterSpec
import com.pbtx.Model.KeyModel
import com.pbtx.errors.AndroidKeyStoreDeleteError
import com.pbtx.errors.AndroidKeyStoreSigningError
import com.pbtx.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import com.pbtx.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import com.pbtx.errors.QueryAndroidKeyStoreError
import com.pbtx.utils.KeyStoreProvider
import com.pbtx.utils.KeyStoreProvider.Companion.generateAndroidKeyStoreKey
import com.pbtx.utils.KeyStoreProvider.Companion.getCompressedPublicKey
import com.pbtx.utils.KeyStoreProvider.Companion.getKeystore
import com.pbtx.utils.PbtxUtils.Companion.additionByteAdd
import com.pbtx.utils.ProtoBufProvider
import com.pbtx.utils.ProtoBufProvider.Companion.getProtobufModels
import com.pbtx.utils.SignatureProvider.Companion.getCanonicalSignature
import pbtx.Pbtx
import java.security.KeyStore
import java.security.Signature
import java.util.*


/**
 * Utility class provides cryptographic methods to manage keys in the Android KeyStore Signature Provider and uses the keys to sign transactions.
 */
class PbtxClient {

    companion object {
        const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val ANDROID_ECDSA_SIGNATURE_ALGORITHM: String = "SHA256withECDSA"

        /**
         * Generate a new key inside AndroidKeyStore by the given [alias] and return the new key in bye[] format
         *
         * The given [alias] is the identity of the key. The new key will be generated with the Default [KeyGenParameterSpec] from the [generateDefaultKeyGenParameterSpecBuilder]
         *
         * @param alias : Alias of the key store
         * @return Key : byte Array of generated public key
         */
        @JvmStatic
        fun createKey(alias: String): Pbtx.PublicKey {
            // Create a default KeyGenParameterSpec
            val keyGenParameterSpec: KeyGenParameterSpec =
                    KeyStoreProvider.generateDefaultKeyGenParameterSpecBuilder(alias).build()

            var keyStore = generateAndroidKeyStoreKey(keyGenParameterSpec)

            val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry

            var compressedPublicKey = getCompressedPublicKey(privateKeyEntry)

            return ProtoBufProvider.createPublicKeyProtoMessage(additionByteAdd(compressedPublicKey))

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
                    var keyModel = getProtobufModels(keyStore, it, null)
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
                val ks: KeyStore = getKeystore(null)
                ks.deleteEntry(alias)
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        /**
         * Sign data with a private and return as a signature.
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

                val compressedPublicKey = getCompressedPublicKey(keyEntry)

                var signature = Signature.getInstance(ANDROID_ECDSA_SIGNATURE_ALGORITHM).run {
                    initSign(keyEntry.privateKey)
                    update(data)
                    sign()
                }

                val canonicalSignature = getCanonicalSignature(signature, data, compressedPublicKey)

                return additionByteAdd(canonicalSignature)

            } catch (ex: Exception) {
                throw AndroidKeyStoreSigningError(ex)
            }

        }

    }

}
