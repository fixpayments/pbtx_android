package ekis.pbtxjavaandroidkeystoresignatureprovider

import android.util.Log
import androidx.test.runner.AndroidJUnit4
import com.google.crypto.tink.subtle.EllipticCurves
import org.junit.Assert
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.junit.runner.RunWith
import java.lang.Exception
import java.security.KeyFactory
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

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

        PbtxEkis.generateAndroidKeyStoreKey(TEST_CONST_TEST_KEY_NAME)

        var mPublicKeys = PbtxEkis.publicKey(
            password = null,
            "0102030405060708090a0b0c0d0e0f".toByteArray(),
            loadStoreParameter = null
        )

        Log.e("TAG", "public_keys:" + mPublicKeys.size)


    }

}