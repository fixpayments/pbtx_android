package com.pbtx

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import com.google.protobuf.ByteString
import com.pbtx.errors.AndroidKeyStoreDeleteError
import com.pbtx.errors.AndroidKeyStoreSigningError
import com.pbtx.errors.ErrorString.Companion.DELETE_KEY_KEYSTORE_GENERIC_ERROR
import com.pbtx.errors.ErrorString.Companion.QUERY_ANDROID_KEYSTORE_GENERIC_ERROR
import com.pbtx.errors.QueryAndroidKeyStoreError
import com.pbtx.model.KeyModel
import com.pbtx.persistence.PbtxDatabase
import com.pbtx.persistence.entities.AccountRecord
import com.pbtx.persistence.entities.RegistrationRecord
import com.pbtx.persistence.entities.RegistrationStatus
import com.pbtx.utils.KeyStoreProvider
import com.pbtx.utils.KeyStoreProvider.Companion.generateAndroidKeyStoreKey
import com.pbtx.utils.KeyStoreProvider.Companion.getCompressedPublicKey
import com.pbtx.utils.PbtxUtils.Companion.additionByteAdd
import com.pbtx.utils.ProtobufProvider
import com.pbtx.utils.SignatureProvider.Companion.getCanonicalSignature
import pbtx.*
import java.security.KeyStore
import java.security.Signature
import java.util.*


/**
 * Utility class provides cryptographic methods to manage keys in the Android KeyStore Signature Provider and uses the keys to sign transactions.
 */
class PbtxClient constructor(context: Context) {

    private val pbtxDatabase = PbtxDatabase.getInstance(context)
    private val accountDao = pbtxDatabase.accountDao()
    private val registrationDao = pbtxDatabase.registrationDao()

    fun initRegistration(): KeyModel {
        val keyModel = createRandomKey()
        val registrationRecord = RegistrationRecord(keyModel.publicKey.keyBytes.toString(), keyModel.alias)
        registrationDao.insert(registrationRecord)
        return keyModel
    }

    fun registerAccount(networkId: Long, permission: Permission, seqNumber: Int = 0, prevHash: Long = 0) {
        val actor = permission.actor
        val weightedKey = permission.getKeys(0) //we expect only one key, used in registration/kyc process
            ?: throw Exception("A public key was not provided in the permission object")
        val publicKeyString = weightedKey.key.keyBytes.toString()

        val registrationRecord = registrationDao.getRegistrationRecord(publicKeyString)
            ?: throw Exception("Registration record not found for the provided public key = $publicKeyString")

        if (registrationRecord.status == RegistrationStatus.COMPLETED)
            throw Exception("The registration process was already completed for actor = $actor, public key = $publicKeyString")

        val account = AccountRecord(networkId, actor, seqNumber, prevHash, registrationRecord.publicKey, registrationRecord.keyAlias)
        accountDao.insert(account)

        registrationRecord.status = RegistrationStatus.COMPLETED
        registrationDao.update(registrationRecord)
    }

    fun getLocalSyncHead(networkId: Long, actor: Long): Pair<Int, Long> {
        val accountDetails = accountDao.getAccount(networkId, actor)
            ?: throw RuntimeException("AccountDetails not initialized")

        return Pair(accountDetails.seqNumber, accountDetails.prevHash)
    }

    fun updateLocalSyncHead(networkId: Long, actor: Long, seqNumber: Int, prevHash: Long) {
        val accountDetails = accountDao.getAccount(networkId, actor)
            ?: throw RuntimeException("AccountDetails not initialized")

        accountDetails.seqNumber = seqNumber
        accountDetails.prevHash = prevHash

        accountDao.update(accountDetails)
    }

    fun signTransaction(networkId: Long, actor: Long, transactionType: Int, transactionContent: ByteArray): Transaction {
        val account = accountDao.getAccount(networkId, actor)
            ?: throw Exception("Account not registered on this device [networkId = $networkId, actor = $actor]")

        val (seqNumber, prevHash) = getLocalSyncHead(networkId, actor)
        val transactionBody = TransactionBody.newBuilder()
            .setNetworkId(networkId)
            .setActor(actor)
            .setSeqnum(seqNumber + 1)
            .setPrevHash(prevHash)
            .setTransactionType(transactionType)
            .setTransactionContent(ByteString.copyFrom(transactionContent))
            .build()

        val actorSignature = signData(transactionBody.toByteArray(), account.keyAlias)
        val actorSignatureByteString = ByteString.copyFrom(actorSignature)

        val authority = Authority.newBuilder()
            .setType(KeyType.EOSIO_KEY)
            .addSigs(actorSignatureByteString)

        return Transaction.newBuilder()
            .setBody(transactionBody.toByteString())
            .addAuthorities(authority)
            .build()
    }

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
        fun createKey(alias: String): ByteArray {
            // Create a default KeyGenParameterSpec
            val keyGenParameterSpec: KeyGenParameterSpec =
                KeyStoreProvider.generateDefaultKeyGenParameterSpecBuilder(alias).build()

            var keyStore = getKeyStoreInstance()
            keyStore.load(null)


            var privateKeyEntry = loadKeyAlias(alias, keyStore)
            if (privateKeyEntry == null) {
                generateAndroidKeyStoreKey(keyGenParameterSpec)
                privateKeyEntry = loadKeyAlias(alias, keyStore)
            }

            var compressedPublicKey = getCompressedPublicKey(privateKeyEntry!!)

            return additionByteAdd(compressedPublicKey)

        }

        private fun createRandomKey(): KeyModel {
            val keyAlias = "EKIS-" + UUID.randomUUID().toString()
            val publicKeyBytes = createKey(keyAlias)
            val publicKey = ProtobufProvider.createPublicKeyProtoMessage(publicKeyBytes)
            return KeyModel(publicKey, keyAlias)
        }

        private fun loadKeyAlias(alias: String, keyStore: KeyStore): KeyStore.PrivateKeyEntry? {
            return keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry?
        }


        /**
         * Get all (SECP256R1) keys in byte format from Android KeyStore
         * @return Array of public Keys with the alias.
         */

        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun listKeys(): ArrayList<KeyModel> {
            var mList: ArrayList<KeyModel> = ArrayList()

            try {
                val keyStore = getKeyStoreInstance()
                keyStore.load(null)
                var aliasList = keyStore.aliases().toList()
                aliasList.forEach {
                    var keyModel = ProtobufProvider.getProtobufModels(keyStore, it, null)
                    mList.add(keyModel)
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                throw QueryAndroidKeyStoreError(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR, ex)
            }

            return mList
        }

        /**
         * Get all (SECP256R1) keys in byte format from Android KeyStore
         * @return Array of public Keys with the alias.
         */

        @Throws(QueryAndroidKeyStoreError::class)
        @JvmStatic
        fun getKey(alias: String): ByteArray? {
            var pubKey: KeyStore.PrivateKeyEntry? = null
            try {
                val keyStore = getKeyStoreInstance()
                keyStore.load(null)
                pubKey = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry

            } catch (ex: Exception) {
                ex.printStackTrace()
                throw QueryAndroidKeyStoreError(QUERY_ANDROID_KEYSTORE_GENERIC_ERROR, ex)
            }
            var compressedPublicKey = getCompressedPublicKey(pubKey)

            return additionByteAdd(compressedPublicKey)
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
        fun getPublicKeyObject(): PublicKey {
            return PublicKey.getDefaultInstance()
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
        fun signData(data: ByteArray, alias: String): ByteArray {
            try {

                var keyStore = getKeyStoreInstance()
                keyStore.load(null)

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
    }

}
