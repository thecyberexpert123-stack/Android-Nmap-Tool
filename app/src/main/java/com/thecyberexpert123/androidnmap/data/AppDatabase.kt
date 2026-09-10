package com.thecyberexpert123.androidnmap.data

import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import androidx.room.Dao
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Upsert
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

@Database(
    entities = [
        ScanProfileEntity::class,
        AutomationScheduleEntity::class,
        ScanRunEntity::class,
    ],
    version = 4,
    exportSchema = false,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun scanProfileDao(): ScanProfileDao
    abstract fun automationScheduleDao(): AutomationScheduleDao
    abstract fun scanRunDao(): ScanRunDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(database: SupportSQLiteDatabase) {
                database.execSQL("ALTER TABLE scan_runs ADD COLUMN nmapXmlOutput TEXT")
            }
        }

        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(database: SupportSQLiteDatabase) {
                database.execSQL("ALTER TABLE scan_runs ADD COLUMN stdoutTruncated INTEGER NOT NULL DEFAULT 0")
                database.execSQL("ALTER TABLE scan_runs ADD COLUMN stderrTruncated INTEGER NOT NULL DEFAULT 0")
                database.execSQL("ALTER TABLE scan_runs ADD COLUMN nmapXmlOutputTruncated INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(database: SupportSQLiteDatabase) {
                database.execSQL("ALTER TABLE scan_runs ADD COLUMN requestId TEXT")
                database.execSQL("ALTER TABLE scan_runs ADD COLUMN executorLabel TEXT")
            }
        }
    }
}

@Entity(tableName = "scan_profiles")
data class ScanProfileEntity(
    @PrimaryKey val id: String,
    val name: String,
    val toolType: String,
    val executionPreference: String,
    val rawTargets: String,
    val rawArguments: String,
    val notes: String,
    val createdAtEpochMillis: Long,
    val updatedAtEpochMillis: Long,
)

@Entity(tableName = "automation_schedules")
data class AutomationScheduleEntity(
    @PrimaryKey val profileId: String,
    val repeatMinutes: Long,
    val requireUnmeteredNetwork: Boolean,
    val enabled: Boolean,
    val updatedAtEpochMillis: Long,
)

@Entity(
    tableName = "scan_runs",
    indices = [Index(value = ["profileId"]), Index(value = ["startedAtEpochMillis"])],
)
data class ScanRunEntity(
    @PrimaryKey val id: String,
    val profileId: String?,
    val profileName: String,
    val toolType: String,
    val route: String,
    val status: String,
    val triggerSource: String,
    val commandPreview: String,
    val exitCode: Int?,
    val stdout: String,
    val stderr: String,
    val message: String,
    val startedAtEpochMillis: Long,
    val finishedAtEpochMillis: Long,
    val nmapXmlOutput: String?,
    val stdoutTruncated: Boolean,
    val stderrTruncated: Boolean,
    val nmapXmlOutputTruncated: Boolean,
    val requestId: String?,
    val executorLabel: String?,
)

@Dao
interface ScanProfileDao {
    @Query("SELECT * FROM scan_profiles ORDER BY updatedAtEpochMillis DESC")
    fun observeAll(): Flow<List<ScanProfileEntity>>

    @Query("SELECT * FROM scan_profiles WHERE id = :profileId")
    suspend fun getById(profileId: String): ScanProfileEntity?

    @Upsert
    suspend fun upsert(entity: ScanProfileEntity)
}

@Dao
interface AutomationScheduleDao {
    @Query("SELECT * FROM automation_schedules ORDER BY updatedAtEpochMillis DESC")
    fun observeAll(): Flow<List<AutomationScheduleEntity>>

    @Query("SELECT * FROM automation_schedules WHERE profileId = :profileId")
    suspend fun getByProfileId(profileId: String): AutomationScheduleEntity?

    @Upsert
    suspend fun upsert(entity: AutomationScheduleEntity)

    @Query("DELETE FROM automation_schedules WHERE profileId = :profileId")
    suspend fun deleteByProfileId(profileId: String)
}

@Dao
interface ScanRunDao {
    @Query("SELECT * FROM scan_runs ORDER BY startedAtEpochMillis DESC LIMIT 100")
    fun observeRecent(): Flow<List<ScanRunEntity>>

    @Upsert
    suspend fun upsert(entity: ScanRunEntity)
}
