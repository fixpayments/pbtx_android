package com.pbtx.utils

class ApplicationUtils {

    companion object {
        fun isTestMode(): Boolean {
            val result: Boolean = try {
                Class.forName("com.pbtx.PbtxDatabaseTest")
                true
            } catch (e: Exception) {
                false
            }
            return result
        }
    }
}