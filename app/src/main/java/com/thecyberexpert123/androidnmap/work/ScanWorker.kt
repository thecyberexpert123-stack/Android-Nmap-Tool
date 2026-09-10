package com.thecyberexpert123.androidnmap.work

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.thecyberexpert123.androidnmap.NmapToolApplication
import com.thecyberexpert123.nmaptool.contract.RunTrigger

class ScanWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val profileId = inputData.getString(KEY_PROFILE_ID) ?: return Result.failure()
        setForeground(createForegroundInfo(profileId))

        val repository = (applicationContext as NmapToolApplication).appContainer.repository
        return runCatching {
            repository.executeProfile(profileId = profileId, trigger = RunTrigger.SCHEDULED)
            Result.success()
        }.getOrElse {
            Result.retry()
        }
    }

    private fun createForegroundInfo(profileId: String): ForegroundInfo {
        ensureNotificationChannel()
        val notification = Notification.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("Scheduled scan in progress")
            .setContentText("Running automation profile $profileId")
            .setOngoing(true)
            .build()

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            ForegroundInfo(NOTIFICATION_ID, notification)
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = applicationContext.getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Android Nmap Tool automation",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Foreground notifications for scheduled network scans"
        }
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val KEY_PROFILE_ID = "profile_id"
        const val KEY_REQUIRE_UNMETERED = "require_unmetered"
        private const val CHANNEL_ID = "scheduled_scans"
        private const val NOTIFICATION_ID = 2_431
    }
}
