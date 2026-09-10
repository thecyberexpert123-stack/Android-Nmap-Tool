package com.thecyberexpert123.androidnmap.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.thecyberexpert123.androidnmap.data.AutomationScheduleDao
import com.thecyberexpert123.androidnmap.data.AutomationScheduleEntity
import java.util.concurrent.TimeUnit

private const val MIN_REPEAT_MINUTES = 15L

class AutomationScheduler(
    private val context: Context,
    private val scheduleDao: AutomationScheduleDao,
) {
    suspend fun syncSchedule(
        profileId: String,
        enabled: Boolean,
        repeatMinutes: Long?,
        requireUnmeteredNetwork: Boolean,
    ) {
        val workManager = WorkManager.getInstance(context)
        val uniqueWorkName = uniqueWorkName(profileId)

        if (!enabled || repeatMinutes == null) {
            workManager.cancelUniqueWork(uniqueWorkName)
            scheduleDao.deleteByProfileId(profileId)
            return
        }

        require(repeatMinutes >= MIN_REPEAT_MINUTES) {
            "Periodic automation must be at least $MIN_REPEAT_MINUTES minutes."
        }

        val constraints = Constraints.Builder()
            .setRequiredNetworkType(
                if (requireUnmeteredNetwork) NetworkType.UNMETERED else NetworkType.CONNECTED,
            )
            .build()

        val workRequest = PeriodicWorkRequestBuilder<ScanWorker>(repeatMinutes, TimeUnit.MINUTES)
            .setInputData(
                workDataOf(
                    ScanWorker.KEY_PROFILE_ID to profileId,
                    ScanWorker.KEY_REQUIRE_UNMETERED to requireUnmeteredNetwork,
                ),
            )
            .setConstraints(constraints)
            .addTag(uniqueWorkName)
            .build()

        workManager.enqueueUniquePeriodicWork(
            uniqueWorkName,
            ExistingPeriodicWorkPolicy.UPDATE,
            workRequest,
        )

        scheduleDao.upsert(
            AutomationScheduleEntity(
                profileId = profileId,
                repeatMinutes = repeatMinutes,
                requireUnmeteredNetwork = requireUnmeteredNetwork,
                enabled = true,
                updatedAtEpochMillis = System.currentTimeMillis(),
            ),
        )
    }

    fun cancel(profileId: String) {
        WorkManager.getInstance(context).cancelUniqueWork(uniqueWorkName(profileId))
    }

    private fun uniqueWorkName(profileId: String): String = "scheduled-scan-$profileId"
}
