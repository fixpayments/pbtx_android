package com.pbtx.utils

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


    }
}