package ekis.PBTX

import android.util.Log
import androidx.test.runner.AndroidJUnit4
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith

/**
 * Test class for [ekisAndroidKeyStoreSignatureProvider]
 */
@RunWith(AndroidJUnit4::class)
class EkisTest {

    companion object {
        const val TEST_CONST_TEST_KEY_NAME = "test_key"
    }

    @Rule
    @JvmField
    val exceptionRule: ExpectedException = ExpectedException.none()

    /**
     * Test [EkisTest.createKey] method
     *
     * Generate new key and print hex string.
     */
    @Test
    fun createKeyTest() {

        // Creating a new key
        var key = PbtxEkis.createKey(TEST_CONST_TEST_KEY_NAME)
        Log.d("EKisTest", "Key :: " + key.toHexString())
        Assert.assertNotNull(key)
        // Check if the key present in the size
        assert(PbtxEkis.listKeys().size == 1)
    }

    @Test
    fun listKeysTest() {

        // list of the keys present in the stores.
        var keyList = PbtxEkis.listKeys()

        keyList.forEach() {
            Log.d("EKisTest", "Key :: " + it.key.toHexString())
        }
        assert(keyList.size == 1)
    }


    @Test
    fun signDataTest() {

        var mPublicKeys: ByteArray? = PbtxEkis.signData("0102030405060708090a0b0c0d0e0f".toByteArray(),
                TEST_CONST_TEST_KEY_NAME)
        Log.d("EKisTest", "signedData :: " + mPublicKeys?.size)
        Assert.assertNotNull(mPublicKeys)
    }

    @Test
    fun deleteKeyTest() {
        // Use the key that was just added to the keystore to sign a transaction.
        PbtxEkis.deleteKey(TEST_CONST_TEST_KEY_NAME)
        // Check the size after deleting the store it should be 0 key present in the store.
        assert(PbtxEkis.listKeys().size == 0)
    }

    fun ByteArray.toHexString(): String {
        return this.joinToString("") {
            java.lang.String.format("%02x", it)
        }
    }
}