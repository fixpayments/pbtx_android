package com.pbtx.persistence

import android.content.Context
import androidx.room.AutoMigration
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.pbtx.persistence.daos.AccountDao
import com.pbtx.persistence.daos.RegistrationDao
import com.pbtx.persistence.daos.TransactionHistoryDao
import com.pbtx.persistence.entities.AccountRecord
import com.pbtx.persistence.entities.RegistrationRecord
import com.pbtx.persistence.entities.TransactionHistoryRecord
import com.pbtx.utils.ApplicationUtils

@Database(
    entities = [RegistrationRecord::class, AccountRecord::class, TransactionHistoryRecord::class],
    version = 3,
    autoMigrations = [
        AutoMigration(from = 2, to = 3)
    ]
)
abstract class PbtxDatabase : RoomDatabase() {
    abstract fun registrationDao(): RegistrationDao
    abstract fun accountDao(): AccountDao
    abstract fun transactionHistoryDao(): TransactionHistoryDao

    companion object {
        @Volatile
        private var INSTANCE: PbtxDatabase? = null

        @JvmStatic
        fun getInstance(context: Context): PbtxDatabase {
            return INSTANCE ?: synchronized(this) {
                return INSTANCE ?: run {
                    val instance =
                        if (ApplicationUtils.isTestMode())
                            Room.inMemoryDatabaseBuilder(context, PbtxDatabase::class.java)
                                .build()
                        else
                            Room.databaseBuilder(context, PbtxDatabase::class.java, "pbtx_database")
                                .build()

                    INSTANCE = instance
                    return instance
                }
            }
        }
    }
}