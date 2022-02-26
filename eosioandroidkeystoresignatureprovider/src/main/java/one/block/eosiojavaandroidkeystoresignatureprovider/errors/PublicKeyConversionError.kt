package one.block.eosiojavaandroidkeystoresignatureprovider.errors

import one.block.eosiojava.error.signatureProvider.SignatureProviderError
import org.jetbrains.annotations.NotNull
import java.lang.Exception

/**
 * Error class that will be thrown from [one.block.eosiojavaandroidkeystoresignatureprovider.EosioAndroidKeyStoreUtility.convertAndroidKeyStorePublicKeyToEOSFormat]
 */
class PublicKeyConversionError : SignatureProviderError {
    constructor(message: @NotNull String) : super(message)
}