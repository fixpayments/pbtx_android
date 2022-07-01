package com.pbtx.persistence.daos

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import com.pbtx.persistence.entities.AccountRecord

@Dao
interface AccountDao {
    @Query("SELECT * FROM accounts where network_id = :networkId and actor = :actor")
    suspend fun getAccount(networkId: Long, actor: Long): AccountRecord?

    @Insert
    suspend fun insert(accountRecord: AccountRecord)

    @Update
    suspend fun update(accountRecord: AccountRecord)
}