package com.pbtx.persistence.daos

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import com.pbtx.persistence.entities.TransactionHistoryRecord

@Dao
interface TransactionHistoryDao {
    @Query(
        "SELECT * FROM transaction_history " +
                "WHERE network_id = :networkId AND actor = :actor " +
                "ORDER BY backend_timestamp DESC " +
                "LIMIT :pageSize OFFSET :pageNumber"
    )
    suspend fun getTransactions(networkId: Long, actor: Long, pageNumber: Int, pageSize: Int): List<TransactionHistoryRecord>

    @Query(
        "SELECT * FROM transaction_history " +
                "WHERE network_id = :networkId AND actor = :actor AND backend_trx_id = :backendTransactionId " +
                "LIMIT 1"
    )
    suspend fun getTransaction(networkId: Long, actor: Long, backendTransactionId: ByteArray): TransactionHistoryRecord?

    @Insert
    suspend fun insert(transactionHistoryRecord: TransactionHistoryRecord)

    @Update
    suspend fun update(transactionHistoryRecord: TransactionHistoryRecord)
}