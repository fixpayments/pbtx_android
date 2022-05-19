package com.pbtx

import android.util.Log
import androidx.test.runner.AndroidJUnit4
import org.junit.*
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import java.util.*

/**
 * Test class for [ekisAndroidKeyStoreSignatureProvider]
 */
@RunWith(AndroidJUnit4::class)
class PbtxClientTest {

    @Rule
    @JvmField
    val exceptionRule: ExpectedException = ExpectedException.none()

    @Test
    fun createAndDeleteKey() {
        val initialKeyListSize = PbtxClient.listKeys().size

        // Creating a new key
        val keyName = randomKeyName()
        val key = PbtxClient.createKey(keyName)

        Log.d("EKisTest", "Key :: " + key.toHexString())
        Assert.assertNotNull(key)

        // Check if the key present in the size
        assert(PbtxClient.listKeys().size == initialKeyListSize + 1)

        // Deleting key
        PbtxClient.deleteKey(keyName)

        // Check the store size after deleting the key
        assert(PbtxClient.listKeys().size == initialKeyListSize)
    }

    @Test
    fun listKeysTest() {
        val initialKeyListSize = PbtxClient.listKeys().size

        // Creating keys
        val keyName1 = randomKeyName()
        val keyName2 = randomKeyName()
        PbtxClient.createKey(keyName1)
        PbtxClient.createKey(keyName2)

        // List of the keys present in the stores
        val keyList = PbtxClient.listKeys()

        keyList.forEach {
            Log.d("EKisTest", "Key :: " + it.key.toByteArray().toHexString())
        }
        assert(keyList.size == initialKeyListSize + 2)

        // Cleanup
        PbtxClient.deleteKey(keyName1)
        PbtxClient.deleteKey(keyName2)
        assert(PbtxClient.listKeys().size == initialKeyListSize)
    }


    @Test
    fun signDataTest() {
        // Creating key
        val keyName = randomKeyName()
        PbtxClient.createKey(keyName)

        // Signing data
        val signature: ByteArray? = PbtxClient.signData(
            "0102030405060708090a0b0c0d0e0f".decodeHex(),
            keyName
        )
        Log.d("EKisTest", "Signature ${signature?.toHexString()}")
        Assert.assertNotNull(signature)

        // Cleanup
        PbtxClient.deleteKey(keyName)
    }

    private fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }

        val byteIterator = chunkedSequence(2)
            .map { it.toInt(16).toByte() }
            .iterator()

        return ByteArray(length / 2) { byteIterator.next() }
    }

    private fun ByteArray.toHexString(): String {
        return this.joinToString("") {
            java.lang.String.format("%02x", it)
        }
    }

    private fun randomKeyName(): String {
        return "random" + UUID.randomUUID().toString()
    }
}