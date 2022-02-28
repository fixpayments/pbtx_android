package one.block.pbtxjavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.SignatureProviderError
import org.jetbrains.annotations.NotNull
import java.lang.Exception

/**
 * Error class that will be thrown from [one.block.pbtxjavaandroidkeystoresignatureprovider.PbtxKeyStoreUtility.sign]
 */
class AndroidKeyStoreSigningError : SignatureProviderError {
    constructor(exception: @NotNull Exception) : super(exception)
}