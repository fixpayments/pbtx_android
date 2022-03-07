package one.block.pbtxjavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.SignatureProviderError
import org.jetbrains.annotations.NotNull

/**
 * Error class that will be thrown from [one.block.pbtxjavaandroidkeystoresignatureprovider.PbtxKeyStoreUtility.convertAndroidKeyStorePublicKeyToEOSFormat]
 */
class PublicKeyConversionError : SignatureProviderError {
    constructor(message: @NotNull String) : super(message)
}