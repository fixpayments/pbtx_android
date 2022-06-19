package com.pbtx.persistence.daos

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import com.pbtx.persistence.entities.AccountRecord

@Dao
interface AccountDao {
    @Query("SELECT * FROM accounts where network_id = :networkId and actor = :actor")
    fun getAccount(networkId: Long, actor: Long): AccountRecord?

    @Insert
    fun insert(accountRecord: AccountRecord)

    @Update
    fun update(accountRecord: AccountRecord)
}