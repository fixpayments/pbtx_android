package io.ekis.sample

import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import io.ekis.sample.Model.KeyModel
import io.ekis.sample.errors.AndroidKeyStoreDeleteError
import io.ekis.sample.errors.AndroidKeyStoreSigningError
import io.ekis.sample.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import io.ekis.sample.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import io.ekis.sample.errors.QueryAndroidKeyStoreError
import io.ekis.sample.utils.KeyStoreProvider
import io.ekis.sample.utils.KeyStoreProvider.Companion.generateAndroidKeyStoreKey
import io.ekis.sample.utils.KeyStoreProvider.Companion.getCompressedPublicKey
import io.ekis.sample.utils.KeyStoreProvider.Companion.getKeystore
import io.ekis.sample.utils.PbtxUtils.Companion.additionByteAdd
import io.ekis.sample.utils.ProtoBufProvider
import io.ekis.sample.utils.ProtoBufProvider.Companion.getProtobufModels
import io.ekis.sample.utils.SignatureProvider.Companion.getCanonicalSignature
import pbtx.Pbtx
import java.security.Key
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
        private var KEYSTORE_INSTANCE: KeyStore? = null
        private var SIGNATURE_INSTANCE: Signature? = null

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

            var keyStore = getKeyStoreInstance()
            keyStore.load(null);

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
                val keyStore = getKeyStoreInstance()
                keyStore.load(null);
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
         * Get all (SECP256R1) keys in byte format from Android KeyStore
         * @return Array of public Keys with the alias.
         */

        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun getKey(alias: String): Pbtx.PublicKey? {
            var pubKey: KeyStore.PrivateKeyEntry? = null
            try {
                val keyStore = getKeyStoreInstance()
                keyStore.load(null);
                pubKey = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry

            } catch (ex: Exception) {
                ex.printStackTrace()
                throw QueryAndroidKeyStoreError(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR, ex)
            }
            var compressedPublicKey = getCompressedPublicKey(pubKey)

            return ProtoBufProvider.createPublicKeyProtoMessage(additionByteAdd(compressedPublicKey))
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
                val ks: KeyStore = getKeyStoreInstance()
                ks.deleteEntry(alias)
            } catch (ex: Exception) {
                throw AndroidKeyStoreDeleteError(DELETE_KEY_KEYSTORE_GENERIC_ERROR, ex)
            }
        }

        @JvmStatic
        fun getPublicKeyObject(): Pbtx.PublicKey {
            return Pbtx.PublicKey.getDefaultInstance()
        }

        @JvmStatic
        fun getKeyStoreInstance(): KeyStore {
            var keyStore: KeyStore? = null
            keyStore = if (KEYSTORE_INSTANCE == null) {
                KeyStore.getInstance("AndroidKeyStore").apply {
                    load(null)
                }
            } else {
                KEYSTORE_INSTANCE
            }
            KEYSTORE_INSTANCE = keyStore
            //generateAndroidKeyStoreKey(keyGenParameterSpec)
            return keyStore!!
        }

        @JvmStatic
        fun getSignatureInstance(): Signature {
            var signatureInstace: Signature? = null
            signatureInstace = if (SIGNATURE_INSTANCE == null) {
                Signature.getInstance(ANDROID_ECDSA_SIGNATURE_ALGORITHM)
            } else {
                SIGNATURE_INSTANCE
            }
            SIGNATURE_INSTANCE = signatureInstace
            //generateAndroidKeyStoreKey(keyGenParameterSpec)
            return signatureInstace!!
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

                var keyStore = getKeyStoreInstance()
                keyStore.load(null);

                val keyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
                Log.d("Key Entry Sign Data:", keyEntry.toString())

                val compressedPublicKey = getCompressedPublicKey(keyEntry)

                var signature = getSignatureInstance().run {
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
        fun signDataV2(data: ByteArray, alias: String): ByteArray? {
            try {

                val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
                    load(null)
                }
                val entry: KeyStore.Entry = ks.getEntry(alias, null)
                if (entry !is KeyStore.PrivateKeyEntry) {
                    Log.w("N", "Not an instance of a PrivateKeyEntry")
                    return null
                }
                Log.d("Key Entry Sign Data:", entry.toString())
                val signature: ByteArray = Signature.getInstance(ANDROID_ECDSA_SIGNATURE_ALGORITHM).run {
                    initSign(entry.privateKey)
                    update(data)
                    sign()
                }

                val compressedPublicKey = getCompressedPublicKey(entry)

                val canonicalSignature = getCanonicalSignature(signature, data, compressedPublicKey)

                return additionByteAdd(canonicalSignature)

            } catch (ex: Exception) {
                throw AndroidKeyStoreSigningError(ex)
            }

        }

    }

}
