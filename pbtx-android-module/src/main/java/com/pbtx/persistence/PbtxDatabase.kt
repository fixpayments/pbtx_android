package com.pbtx.persistence

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.pbtx.persistence.daos.AccountDao
import com.pbtx.persistence.daos.RegistrationDao
import com.pbtx.persistence.entities.AccountRecord
import com.pbtx.persistence.entities.RegistrationRecord

@Database(entities = [RegistrationRecord::class, AccountRecord::class], version = 2)
abstract class PbtxDatabase : RoomDatabase() {
    abstract fun registrationDao(): RegistrationDao
    abstract fun accountDao(): AccountDao

    companion object {
        @Volatile
        private var INSTANCE: PbtxDatabase? = null

        @JvmStatic
        fun getInstance(context: Context): PbtxDatabase {
            return INSTANCE ?: synchronized(this) {
                return INSTANCE ?: run {
                    val instance = Room
                        .inMemoryDatabaseBuilder(context, PbtxDatabase::class.java) //TODO mcicu: use in-memory db only for tests
                        //.databaseBuilder(context, PbtxDatabase::class.java, "pbtx_database")
                        .build()
                    INSTANCE = instance
                    return instance
                }
            }
        }
    }
}