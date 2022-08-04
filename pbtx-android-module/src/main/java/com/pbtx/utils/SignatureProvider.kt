package com.pbtx.utils

import com.google.common.base.Preconditions
import com.google.common.primitives.Bytes
import com.pbtx.enum.AlgorithmEmployed
import org.bitcoinj.core.ECKey
import org.bitcoinj.core.Sha256Hash
import org.bitcoinj.core.Utils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9IntegerConverter
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECAlgorithms
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.FixedPointUtil
import java.io.IOException
import java.math.BigInteger
import java.util.*

class SignatureProvider {
    companion object {

        /**
         * EC holder of R1 key type
         */
        private val CURVE_R1: ECDomainParameters?;

        /**
         * EC parameters holder of R1 key type
         */
        private val CURVE_PARAMS_R1 = CustomNamedCurves.getByName("secp256r1")

        /**
         * Half curve value of R1 key type (to calculate low S)
         */
        private val HALF_CURVE_ORDER_R1: BigInteger

        /**
         * EC holder of K1 key type
         */
        private val CURVE_K1: ECDomainParameters?

        /**
         * EC parameters holder of K1 key type
         */
        private val CURVE_PARAMS_K1 = CustomNamedCurves.getByName("secp256k1")

        /**
         * Half curve value of K1 key type (to calculate low S)
         */
        private val HALF_CURVE_ORDER_K1: BigInteger

        /**
         * The algorithm used to generate the object is unsupported.
         */
        private const val UNSUPPORTED_ALGORITHM = "Unsupported algorithm!"

        /**
         * A public key could not be recovered from the signature.
         */
        private const val COULD_NOT_RECOVER_PUBLIC_KEY_FROM_SIG = "Could not recover public key from Signature."

        /**
         * EC domain parameters of R1 key
         */
        private val ecParamsR1: ECDomainParameters?

        /**
         * EC domain parameters of K1 key
         */
        private val ecParamsK1: ECDomainParameters?

        private const val NUMBER_OF_POSSIBLE_PUBLIC_KEYS = 4
        private const val VALUE_TO_ADD_TO_SIGNATURE_HEADER = 31
        private const val EXPECTED_R_OR_S_LENGTH = 32
        private const val COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y: Byte = 0x03
        private const val COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y: Byte = 0x02

        /**
         * Const name of secp256r1 curves
         */
        private const val SECP256_R1 = "secp256r1"

        /**
         * Const name of secp256k1 curves
         */
        private const val SECP256_K1 = "secp256k1"


        init {

            val paramsR1 = SECNamedCurves.getByName(SECP256_R1)
            ecParamsR1 = ECDomainParameters(paramsR1.curve, paramsR1.g, paramsR1.n,
                    paramsR1.h)

            val paramsK1 = SECNamedCurves.getByName(SECP256_K1)
            ecParamsK1 = ECDomainParameters(paramsK1.curve, paramsK1.g, paramsK1.n,
                    paramsK1.h)

            FixedPointUtil.precompute(CURVE_PARAMS_R1.g)
            CURVE_R1 = ECDomainParameters(
                    CURVE_PARAMS_R1.curve,
                    CURVE_PARAMS_R1.g,
                    CURVE_PARAMS_R1.n,
                    CURVE_PARAMS_R1.h)
            HALF_CURVE_ORDER_R1 = CURVE_PARAMS_R1.n.shiftRight(1)


            // secp256k1

            // secp256k1
            CURVE_K1 = ECDomainParameters(
                    CURVE_PARAMS_K1.curve,
                    CURVE_PARAMS_K1.g,
                    CURVE_PARAMS_K1.n,
                    CURVE_PARAMS_K1.h)
            HALF_CURVE_ORDER_K1 = CURVE_PARAMS_K1.n.shiftRight(1)
        }

        /**
         * This method converts a signature to a EOS compliant form.  The signature to be converted must
         * be an The ECDSA signature that is a DER encoded ASN.1 sequence of two integer fields (see
         * ECDSA-Sig-Value in rfc3279 section 2.2.3).
         *
         *
         * The DER encoded ECDSA signature follows the following format: Byte 1 - Sequence (Should be
         * 30) Byte 2 - Signature length Byte 3 - R Marker (0x02) Byte 4 - R length Bytes 5 to 37 or 38-
         * R Byte After R - S Marker (0x02) Byte After S Marker - S Length Bytes After S Length - S
         * (always 32-33 bytes) Byte Final - Hash Type
         *
         * @param signature byte array of the singed data
         * @param data raw data
         * @param compressedPublicKey byte[] of the compressed public key
         * @return Canonical Format of the signature.
         */
        fun getCanonicalSignature(signature: ByteArray?, data: ByteArray, compressedPublicKey: ByteArray): ByteArray {
            val ecSignature = decodeFromDER(signature)
            var s = ecSignature.s
            var r = ecSignature.r

            s = checkAndHandleLowS(s, AlgorithmEmployed.SECP256R1)
            var recoverId = getRecoveryId(r, s!!, Sha256Hash.of(data), compressedPublicKey,
                    AlgorithmEmployed.SECP256R1)
            check(recoverId >= 0) { COULD_NOT_RECOVER_PUBLIC_KEY_FROM_SIG }

            //Add RecoveryID + 27 + 4 to create the header byte
            recoverId += VALUE_TO_ADD_TO_SIGNATURE_HEADER
            val headerByte = recoverId.toByte()
            return Bytes
                    .concat(byteArrayOf(headerByte), Utils.bigIntegerToBytes(r, EXPECTED_R_OR_S_LENGTH), Utils.bigIntegerToBytes(s, EXPECTED_R_OR_S_LENGTH))
        }

        /**
         * Getting recovery id from R and S
         *
         * @param r                 - R in DER of Signature
         * @param s                 - S in DER of Signature
         * @param sha256HashMessage - Sha256Hash of signed message
         * @param publicKey         - public key to validate
         * @param keyType           - key type
         * @return - Recovery id of the signature. From 0 to 3. Return -1 if find nothing.
         */
        private fun getRecoveryId(r: BigInteger, s: BigInteger, sha256HashMessage: Sha256Hash,
                                  publicKey: ByteArray, keyType: AlgorithmEmployed): Int {
            for (i in 0 until NUMBER_OF_POSSIBLE_PUBLIC_KEYS) {
                val recoveredPublicKey = recoverPublicKeyFromSignature(i, r, s, sha256HashMessage,
                        true, keyType)
                if (Arrays.equals(publicKey, recoveredPublicKey)) {
                    return i
                }
            }
            return -1
        }


        /**
         * * Copyright 2011 Google Inc. * Copyright 2014 Andreas Schildbach * Copyright 2014-2016 the
         * libsecp256k1 contributors * * Licensed under the Apache License, Version 2.0 (the "License");
         * * you may not use this file except in compliance with the License. * You may obtain a copy of
         * the License at * *    http://www.apache.org/licenses/LICENSE-2.0 * * Unless required by
         * applicable law or agreed to in writing, software * distributed under the License is
         * distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
         * express or implied. * See the License for the specific language governing permissions and *
         * limitations under the License.
         *
         *
         * The method was modified to match what we need
         *
         *
         * Given the components of a signature and a selector value, recover and return the public
         * key that generated the signature according to the algorithm in SEC1v2 section 4.1.6.
         *
         *
         * The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the
         * correct one. Because the key recovery operation yields multiple potential keys, the correct
         * key must either be stored alongside the signature, or you must be willing to try each recId
         * in turn until you find one that outputs the key you are expecting.
         *
         *
         * If this method returns null it means recovery was not possible and recId should be
         * iterated.
         *
         *
         * Given the above two points, a correct usage of this method is inside a for loop from 0 to
         * 3, and if the output is null OR a key that is not the one you expect, you try again with the
         * next recId.
         *
         * @param recId      Which possible key to recover.
         * @param r          the R components of the signature, wrapped.
         * @param s          the S components of the signature, wrapped.
         * @param message    Hash of the data that was signed.
         * @param compressed Whether or not the original pubkey was compressed.
         * @param keyType    key type
         * @return An ECKey containing only the public part, or null if recovery wasn't possible.
         */
        private fun recoverPublicKeyFromSignature(recId: Int, r: BigInteger, s: BigInteger,
                                                  message: Sha256Hash, compressed: Boolean, keyType: AlgorithmEmployed): ByteArray? {
            Preconditions.checkArgument(recId >= 0, "recId must be positive")
            Preconditions.checkArgument(r.signum() >= 0, "r must be positive")
            Preconditions.checkArgument(s.signum() >= 0, "s must be positive")

            // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
            //   1.1 Let x = r + jn
            val n: BigInteger // Curve order.
            val g: ECPoint
            val curve: ECCurve.Fp
            when (keyType) {
                AlgorithmEmployed.SECP256R1 -> {
                    n = ecParamsR1!!.n
                    g = ecParamsR1.g
                    curve = ecParamsR1.curve as ECCurve.Fp
                }
                else -> {
                    n = ecParamsK1!!.n
                    g = ecParamsK1.g
                    curve = ecParamsK1.curve as ECCurve.Fp
                }
            }
            val i = BigInteger.valueOf(recId.toLong() / 2)
            val x = r.add(i.multiply(n))

            //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
            //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
            //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
            //        conversion routine specified in Section 2.3.4. If this conversion routine outputs “invalid”, then
            //        do another iteration of Step 1.
            //
            // More concisely, what these points mean is to use X as a compressed public key.
            val prime = curve.q
            if (x.compareTo(prime) >= 0) {
                // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
                return null
            }
            // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
            // So it's encoded in the recId.
            val R = decompressKey(x, recId and 1 == 1, keyType)
            //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
            if (!R?.multiply(n)?.isInfinity!!) {
                return null
            }
            //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
            val e = message.toBigInteger()
            //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
            //   1.6.1. Compute a candidate public key as:
            //               Q = mi(r) * (sR - eG)
            //
            // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
            //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
            // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n). In the above equation
            // ** is point multiplication and + is point addition (the EC group operator).
            //
            // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
            // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
            val eInv = BigInteger.ZERO.subtract(e).mod(n)
            val rInv = r.modInverse(n)
            val srInv = rInv.multiply(s).mod(n)
            val eInvrInv = rInv.multiply(eInv).mod(n)
            val q = ECAlgorithms.sumOfTwoMultiplies(g, eInvrInv, R, srInv)
            return q.getEncoded(compressed)
        }


        /**
         * * Copyright 2011 Google Inc. * Copyright 2014 Andreas Schildbach * Copyright 2014-2016 the
         * libsecp256k1 contributors * * Licensed under the Apache License, Version 2.0 (the "License");
         * * you may not use this file except in compliance with the License. * You may obtain a copy of
         * the License at * *    http://www.apache.org/licenses/LICENSE-2.0 * * Unless required by
         * applicable law or agreed to in writing, software * distributed under the License is
         * distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
         * express or implied. * See the License for the specific language governing permissions and *
         * limitations under the License.
         *
         *
         * The method was modified to match what we need
         *
         *
         * Decompress a compressed public key (x co-ord and low-bit of y-coord).
         */
        private fun decompressKey(xBN: BigInteger, yBit: Boolean, keyType: AlgorithmEmployed): ECPoint? {
            val curve: ECCurve.Fp = when (keyType) {
                AlgorithmEmployed.SECP256R1 -> ecParamsR1?.curve as ECCurve.Fp
                else -> ecParamsK1?.curve as ECCurve.Fp
            }
            val x9 = X9IntegerConverter()
            val compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(curve))
            compEnc[0] = (if (yBit) COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_NEGATIVE_Y else COMPRESSED_PUBLIC_KEY_BYTE_INDICATOR_POSITIVE_Y)
            return curve.decodePoint(compEnc)
        }


        /**
         * Takes the S value of an ECDSA DER encoded signature and converts it to a low value.
         *
         * @param s       S value from signature
         * @param keyType Algorithm used to generate private key that signed the message.
         * @return Low S value
         * @throws LowSVerificationError when the S value determination fails.
         */
        private fun checkAndHandleLowS(s: BigInteger, keyType: AlgorithmEmployed): BigInteger? {
            return if (!isLowS(s, keyType)) {
                when (keyType) {
                    AlgorithmEmployed.SECP256R1 -> CURVE_R1?.n?.subtract(s)
                    else -> CURVE_K1?.n?.subtract(s)
                }
            } else s
        }

        /**
         * Takes the S value of an ECDSA DER encoded signature and determines whether the value is low.
         *
         * @param s       S value from signature
         * @param keyType Algorithm used to generate private key that signed the message.
         * @return boolean indicating whether S value is low
         * @throws LowSVerificationError when the S value determination fails.
         */
        private fun isLowS(s: BigInteger, keyType: AlgorithmEmployed): Boolean {
            val compareResult: Int
            compareResult = when (keyType) {
                AlgorithmEmployed.SECP256R1 -> s.compareTo(HALF_CURVE_ORDER_R1)
                AlgorithmEmployed.SECP256K1 -> s.compareTo(HALF_CURVE_ORDER_K1)
                else -> throw Exception(UNSUPPORTED_ALGORITHM)
            }
            return compareResult == 0 || compareResult == -1
        }


        /**
         * Decoding the signature to ECSignature from DER format.
         *
         * @param signature : Signature signed from private key
         *
         * @return ECDSASignature
         *
         */
        private fun decodeFromDER(signature: ByteArray?): ECKey.ECDSASignature {
            try {
                ASN1InputStream(signature).use { decoder ->
                    val seq = decoder.readObject() as DLSequence
                            ?: throw RuntimeException("Reached past end of ASN.1 stream.")
                    val r: ASN1Integer
                    val s: ASN1Integer
                    try {
                        r = seq.getObjectAt(0) as ASN1Integer
                        s = seq.getObjectAt(1) as ASN1Integer
                    } catch (e: ClassCastException) {
                        throw IllegalArgumentException(e)
                    }
                    return ECKey.ECDSASignature(r.positiveValue, s.positiveValue)
                }
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }
    }
}