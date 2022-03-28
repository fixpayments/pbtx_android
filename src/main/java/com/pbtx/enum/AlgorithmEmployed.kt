package com.pbtx.enum

/**
 * Enum of supported algorithms which are employed in eosio-java library
 */
enum class AlgorithmEmployed
/**
 * Initialize AlgorithmEmployed enum object with a String value
 * @param str - input String value of enums in AlgorithmEmployed
 */(
        /**
         * Gets string value of AlgorithmEmployed's enum
         * @return string value of AlgorithmEmployed's enum
         */
        val string: String) {
    /**
     * Supported SECP256r1 (prime256v1) algorithm curve
     */
    SECP256R1("secp256r1"),

    /**
     * Supported SECP256k1 algorithm curve
     */
    SECP256K1("secp256k1"),

    /**
     * Supported prime256v1 algorithm curve
     */
    PRIME256V1("prime256v1");

}

