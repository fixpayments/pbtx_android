package com.pbtx.persistence.entities

import androidx.room.ColumnInfo
import androidx.room.Entity

@Entity(tableName = "registration", primaryKeys = ["public_key"])
data class RegistrationRecord(
    @ColumnInfo(name = "public_key") val publicKey: String,
    @ColumnInfo(name = "key_alias") val keyAlias: String,
    @ColumnInfo(name = "status") var status: RegistrationStatus = RegistrationStatus.PENDING
)

enum class RegistrationStatus {
    PENDING, COMPLETED
}