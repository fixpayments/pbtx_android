package ekis.PBTX

import androidx.test.runner.AndroidJUnit4
import ekis.PBTX.PbtxEkis.Companion.toHexString
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith

/**
 * Test class for [ekisAndroidKeyStoreSignatureProvider]
 */
@RunWith(AndroidJUnit4::class)
class EkisAndroidKeyStoreSignatureProviderInstrumentedTest {

    companion object {
        const val TEST_CONST_TEST_KEY_NAME = "test_key"
    }

    @Rule
    @JvmField
    val exceptionRule: ExpectedException = ExpectedException.none()

    /**
     * Test [EkisAndroidKeyStoreSignatureProviderInstrumentedTest.generateKeyStoreTest] method
     *
     * Generate new key
     *
     * Making a mocked transaction request
     *
     * Sign transaction
     *
     * Verify transaction with public key
     *
     * Clear key
     */
    @Test
    fun generateKeyStoreTest() {

        // Use the key that was just added to the keystore to sign a transaction.

        PbtxEkis.createKey(TEST_CONST_TEST_KEY_NAME)
    }

    @Test
    fun deleteKeys() {

        // Use the key that was just added to the keystore to sign a transaction.

        PbtxEkis.deleteKey(TEST_CONST_TEST_KEY_NAME)


    }

    @Test
    fun listKeys() {

        // Use the key that was just added to the keystore to sign a transaction.
        var KeyList = PbtxEkis.listKeys()

        KeyList.forEach() {
            System.out.print("Key " + it.key.toHexString());
        }

    }

    @Test
    fun signData() {

        var mPublicKeys : ByteArray?= PbtxEkis.signData(
                "0102030405060708090a0b0c0d0e0f".toByteArray(),
                TEST_CONST_TEST_KEY_NAME
        )

        mPublicKeys?.forEach {
            System.out.print("Key " + it);
        }

    }


}