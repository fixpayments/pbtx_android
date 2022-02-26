package one.block.eosiojavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.SignatureProviderError
import org.jetbrains.annotations.NotNull
import java.lang.Exception

/**
 * Error class that will be thrown when exceptions occur while calling [one.block.eosiojavaandroidkeystoresignatureprovider.EosioAndroidKeyStoreUtility.deleteAllKeys] and [one.block.eosiojavaandroidkeystoresignatureprovider.EosioAndroidKeyStoreUtility.deleteKeyByAlias]
 */
class AndroidKeyStoreDeleteError : SignatureProviderError {
    constructor(message: @NotNull String, exception: @NotNull Exception) : super(message, exception)
}