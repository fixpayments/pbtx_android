package com.pbtx.model

import pbtx.PublicKey

data class KeyModel(
    val publicKey: PublicKey,
    val alias: String
)
