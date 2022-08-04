package com.pbtx.persistence.daos

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import com.pbtx.persistence.entities.RegistrationRecord

@Dao
interface RegistrationDao {

    @Query("SELECT * FROM registration where public_key = :publicKey LIMIT 1")
    suspend fun getRegistrationRecord(publicKey: String): RegistrationRecord?

    @Insert
    suspend fun insert(registrationRecord: RegistrationRecord)

    @Update
    suspend fun update(registrationRecord: RegistrationRecord)
}