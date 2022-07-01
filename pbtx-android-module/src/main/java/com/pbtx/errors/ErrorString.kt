package com.pbtx.errors

/**
 * Error content definition for ekis Signature Provider for AndroidKeyStore and ekis AndroidKeyStore Utility
 */
class ErrorString {
    companion object {
        const val QUERY_ANDROID_KEYSTORE_GENERIC_ERROR = "Something went wrong while querying key(s) in Android KeyStore!"
        const val DELETE_KEY_KEYSTORE_GENERIC_ERROR = "Something went wrong while deleting key(s) in AndroidKeyStore!"
        const val GENERATE_KEY_KEYGENSPEC_MUST_USE_EC = "KeyGenParameterSpec must use ECGenParameterSpec for its algorithm!"
        const val GENERATE_KEY_ECGEN_MUST_USE_SECP256R1 = "ECGenParameterSpec must use a SECP256R1 curve!"
        const val GENERATE_KEY_MUST_HAS_PURPOSE_SIGN = "KeyGenParameterSpec must include KeyProperties.PURPOSE_SIGN!"
    }
}