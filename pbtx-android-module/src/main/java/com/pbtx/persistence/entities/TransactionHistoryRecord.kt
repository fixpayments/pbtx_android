package com.pbtx.persistence.entities

import androidx.room.ColumnInfo
import androidx.room.Entity

@Entity(tableName = "transaction_history", primaryKeys = ["network_id", "actor", "transaction"])
data class TransactionHistoryRecord(
    @ColumnInfo(name = "network_id") val networkId: Long,
    @ColumnInfo(name = "actor") val actor: Long,
    @ColumnInfo(name = "transaction") var transaction: ByteArray,
    @ColumnInfo(name = "backend_timestamp") var backendTimestamp: Long,
    @ColumnInfo(name = "backend_trx_id") var backendTrxId: ByteArray
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TransactionHistoryRecord

        if (networkId != other.networkId) return false
        if (actor != other.actor) return false
        if (!transaction.contentEquals(other.transaction)) return false
        if (backendTimestamp != other.backendTimestamp) return false
        if (!backendTrxId.contentEquals(other.backendTrxId)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = networkId.hashCode()
        result = 31 * result + actor.hashCode()
        result = 31 * result + transaction.contentHashCode()
        result = 31 * result + backendTimestamp.hashCode()
        result = 31 * result + backendTrxId.contentHashCode()
        return result
    }
}