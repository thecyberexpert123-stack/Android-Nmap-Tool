package com.thecyberexpert123.androidnmap

import android.app.Application
import androidx.room.Room
import com.thecyberexpert123.androidnmap.data.AppDatabase
import com.thecyberexpert123.androidnmap.data.DefaultScanRepository
import com.thecyberexpert123.androidnmap.execution.AndroidLocalToolExecutor
import com.thecyberexpert123.androidnmap.execution.RemoteExecutorClient
import com.thecyberexpert123.androidnmap.settings.RemoteSettingsStore
import com.thecyberexpert123.androidnmap.work.AutomationScheduler

class NmapToolApplication : Application() {
    lateinit var appContainer: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()

        val database = Room.databaseBuilder(
            applicationContext,
            AppDatabase::class.java,
            "android-nmap-tool.db",
        ).addMigrations(
            AppDatabase.MIGRATION_1_2,
            AppDatabase.MIGRATION_2_3,
            AppDatabase.MIGRATION_3_4,
        ).build()

        val remoteSettingsStore = RemoteSettingsStore(applicationContext)
        val repository = DefaultScanRepository(
            profileDao = database.scanProfileDao(),
            scheduleDao = database.automationScheduleDao(),
            runDao = database.scanRunDao(),
            remoteSettingsStore = remoteSettingsStore,
            remoteExecutorClient = RemoteExecutorClient(),
            localToolExecutor = AndroidLocalToolExecutor(applicationContext),
        )

        appContainer = AppContainer(
            repository = repository,
            automationScheduler = AutomationScheduler(applicationContext, database.automationScheduleDao()),
        )
    }
}

data class AppContainer(
    val repository: DefaultScanRepository,
    val automationScheduler: AutomationScheduler,
)
