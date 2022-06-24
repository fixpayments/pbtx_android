package com.pbtx.persistence.entities

import androidx.room.ColumnInfo
import androidx.room.Entity

@Entity(tableName = "accounts", primaryKeys = ["network_id", "actor"])
data class AccountRecord(
    @ColumnInfo(name = "network_id") val networkId: Long,
    @ColumnInfo(name = "actor") val actor: Long,
    @ColumnInfo(name = "seq_number") var seqNumber: Int,
    @ColumnInfo(name = "prev_hash") var prevHash: Long,
    @ColumnInfo(name = "public_key") var publicKey: String, //we expect only one key, used in registration/kyc process
    @ColumnInfo(name = "key_alias") var keyAlias: String
)
