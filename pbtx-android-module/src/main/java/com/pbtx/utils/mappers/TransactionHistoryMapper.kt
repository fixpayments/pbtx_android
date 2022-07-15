package com.pbtx.utils.mappers

import com.google.protobuf.ByteString
import com.pbtx.persistence.entities.TransactionHistoryRecord
import pbtx.TransactionHistoryEntry

class TransactionHistoryMapper {

    companion object {

        fun mapToTransactionHistoryRecord(networkId: Long, actor: Long, transactionHistoryEntry: TransactionHistoryEntry): TransactionHistoryRecord {
            return TransactionHistoryRecord(
                networkId,
                actor,
                transactionHistoryEntry.transaction.toByteArray(),
                transactionHistoryEntry.backendTimestamp,
                transactionHistoryEntry.backendTrxid.toByteArray()
            )
        }

        fun mapToTransactionHistoryEntry(transactionHistoryRecord: TransactionHistoryRecord): TransactionHistoryEntry {
            return TransactionHistoryEntry.newBuilder()
                .setTransaction(ByteString.copyFrom(transactionHistoryRecord.transaction))
                .setBackendTimestamp(transactionHistoryRecord.backendTimestamp)
                .setBackendTrxid(ByteString.copyFrom(transactionHistoryRecord.backendTrxId))
                .build()
        }
    }
}