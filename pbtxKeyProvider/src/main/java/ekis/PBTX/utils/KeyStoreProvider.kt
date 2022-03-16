package ekis.PBTX.utils

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.crypto.tink.subtle.EllipticCurves
import ekis.PBTX.PbtxEkis

import ekis.PBTX.errors.ErrorString
import ekis.PBTX.errors.InvalidKeyGenParameter
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

class KeyStoreProvider {

    companion object {

        const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val SECP256R1_CURVE_NAME = "secp256r1"

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
        fun generateDefaultKeyGenParameterSpecBuilder(alias: String): KeyGenParameterSpec.Builder {
            return KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN
            )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(SECP256R1_CURVE_NAME))
        }


        /**
         * Generate a new key inside Android KeyStore by the given [keyGenParameterSpec] and return the new key in EOS format
         *
         * The given [keyGenParameterSpec] is the parameter specification to generate a new key. This specification
         * must include the following information if the key to be generated needs to be EOS Mainnet compliant:
         *
         * - [KeyGenParameterSpec] must include [KeyProperties.PURPOSE_SIGN]
         * - [KeyGenParameterSpec.getAlgorithmParameterSpec] must be of type [ECGenParameterSpec]
         * - [KeyGenParameterSpec.getAlgorithmParameterSpec]'s curve name must be [SECP256R1_CURVE_NAME]
         *
         * @return keystore of android
         */
        @JvmStatic
        fun generateAndroidKeyStoreKey(keyGenParameterSpec: KeyGenParameterSpec): KeyStore {
            // Parameter Spec must include PURPOSE_SIGN
            if (KeyProperties.PURPOSE_SIGN and keyGenParameterSpec.purposes != KeyProperties.PURPOSE_SIGN) {
                throw InvalidKeyGenParameter(ErrorString.GENERATE_KEY_MUST_HAS_PURPOSE_SIGN)
            }

            // Parameter Spec's algorithm spec must be of type ECGenParameterSpec
            if (keyGenParameterSpec.algorithmParameterSpec !is ECGenParameterSpec) {
                throw InvalidKeyGenParameter(ErrorString.GENERATE_KEY_KEYGENSPEC_MUST_USE_EC)
            }

            // The curve of Parameter Spec's algorithm must be SECP256R1
            if ((keyGenParameterSpec.algorithmParameterSpec as ECGenParameterSpec).name != SECP256R1_CURVE_NAME) {
                throw InvalidKeyGenParameter(ErrorString.GENERATE_KEY_ECGEN_MUST_USE_SECP256R1)
            }

            val kpg: KeyPairGenerator =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PbtxEkis.ANDROID_KEYSTORE)
            kpg.initialize(keyGenParameterSpec)
            kpg.generateKeyPair()

            return getKeystore(null)
        }

        /**
         * Loading the key store.
         */
        fun getKeystore(loadStoreParameter: KeyStore.LoadStoreParameter?): KeyStore {
            return KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(loadStoreParameter) }
        }

        /**
         * Compressing the public key from private key entry and convert it to byte Array.
         *
         * @param keyEntry Private Key Entry
         * @return Byte array of compressed public key.
         *
         */
        fun getCompressedPublicKey(keyEntry: KeyStore.PrivateKeyEntry): ByteArray {
            val ecPublicKey =
                    KeyFactory.getInstance(keyEntry.certificate.publicKey.algorithm).generatePublic(
                            X509EncodedKeySpec(keyEntry.certificate.publicKey.encoded)
                    ) as ECPublicKey

            return EllipticCurves.pointEncode(
                    EllipticCurves.CurveType.NIST_P256,
                    EllipticCurves.PointFormatType.COMPRESSED,
                    ecPublicKey.w
            );
        }
    }

}