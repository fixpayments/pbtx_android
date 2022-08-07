package com.pbtx.utils

import pbtx.KeyWeight
import pbtx.Permission
import pbtx.PublicKey

class PbtxUtils {

    companion object {

        /**
         * Adding the additional byte to define the protocol in very first byte.
         */
        fun additionByteAdd(bytes: ByteArray): ByteArray {
            val i = 1
            val b = i.toByte()
            val ba = ByteArray(1)
            ba[0] = b
            // create a destination array that is the size of the two arrays
            val destination = ByteArray(bytes.size + ba.size)

            System.arraycopy(ba, 0, destination, 0, 1)
            System.arraycopy(bytes, 0, destination, 1, bytes.size)

            return destination
        }

        fun decodeHex(input: String): ByteArray {
            check(input.length % 2 == 0) { "Must have an even length" }

            val byteIterator = input.chunkedSequence(2)
                .map { it.toInt(16).toByte() }
                .iterator()
            return ByteArray(input.length / 2) { byteIterator.next() }
        }

        fun bytesToHexString(input: ByteArray): String {
            return input.joinToString("") {
                java.lang.String.format("%02x", it)
            }
        }

        fun buildBasicPermissionForActor(actor: Long, publicKey: PublicKey): Permission {
            return Permission.newBuilder()
                .setActor(actor)
                .addKeys(
                    KeyWeight.newBuilder()
                        .setWeight(1)
                        .setKey(publicKey)
                )
                .build()
        }
    }
}