package one.block.eosiojavaandroidkeystoresignatureprovider

import androidx.test.runner.AndroidJUnit4
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith

/**
 * Test class for [EosioAndroidKeyStoreSignatureProvider]
 */
@RunWith(AndroidJUnit4::class)
class EosioAndroidKeyStoreSignatureProviderInstrumentedTest {

    companion object {
        const val TEST_CONST_TEST_KEY_NAME = "test_key"
    }

    @Rule
    @JvmField
    val exceptionRule: ExpectedException = ExpectedException.none()

    /**
     * Test [EosioAndroidKeyStoreSignatureProvider.signTransaction] method
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
    fun signTransaction() {

        // Use the key that was just added to the keystore to sign a transaction.
        EosioAndroidKeyStoreUtility.generateAndroidKeyStoreKey(TEST_CONST_TEST_KEY_NAME)

            EosioAndroidKeyStoreUtility.getAndroidKeyStoreKeyInEOSFormat(
                alias = TEST_CONST_TEST_KEY_NAME,
                password = null,
                loadStoreParameter = null
        )
        EosioAndroidKeyStoreUtility.deleteAllKeys(loadStoreParameter = null)

    }

    /**
     * Delete a key in Android KeyStore for testing
     */
    private fun deleteKeyInAndroidKeyStore(alias: String ) {
        Assert.assertTrue(
            EosioAndroidKeyStoreUtility.deleteKeyByAlias(
                keyAliasToDelete = alias,
                  loadStoreParameter = null
            )
        )
    }
}