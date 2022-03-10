package ekis.pbtxjavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.SignatureProviderError
import org.jetbrains.annotations.NotNull
import java.lang.Exception

/**
 * Error class that will be thrown when exceptions occur while calling [one.block.pbtxjavaandroidkeystoresignatureprovider.PbtxKeyStoreUtility.deleteAllKeys] and [one.block.pbtxjavaandroidkeystoresignatureprovider.PbtxKeyStoreUtility.deleteKeyByAlias]
 */
class AndroidKeyStoreDeleteError : SignatureProviderError {
    constructor(message: @NotNull String, exception: @NotNull Exception) : super(message, exception)
}