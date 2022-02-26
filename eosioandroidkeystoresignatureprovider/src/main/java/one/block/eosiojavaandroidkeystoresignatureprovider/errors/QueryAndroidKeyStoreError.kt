package one.block.eosiojavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.GetAvailableKeysError
import org.jetbrains.annotations.NotNull
import java.lang.Exception

/**
 * Error class that will be thrown from [one.block.eosiojavaandroidkeystoresignatureprovider.EosioAndroidKeyStoreUtility.getAllAndroidKeyStoreKeysInEOSFormat]
 */
class QueryAndroidKeyStoreError : GetAvailableKeysError {
    constructor(message: @NotNull String, exception: @NotNull Exception) : super(message, exception)
}