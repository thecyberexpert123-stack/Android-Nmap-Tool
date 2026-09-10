package com.thecyberexpert123.androidnmap

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.thecyberexpert123.androidnmap.ui.NmapToolRoot
import com.thecyberexpert123.androidnmap.ui.NmapToolViewModel
import com.thecyberexpert123.androidnmap.ui.theme.AndroidNmapToolTheme

class MainActivity : ComponentActivity() {
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* user decision is respected; scheduling still functions best-effort */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        maybeRequestNotificationPermission()

        val appContainer = (application as NmapToolApplication).appContainer

        setContent {
            AndroidNmapToolTheme {
                val viewModel = viewModel<NmapToolViewModel>(
                    factory = NmapToolViewModel.factory(
                        repository = appContainer.repository,
                        automationScheduler = appContainer.automationScheduler,
                    ),
                )
                NmapToolRoot(viewModel = viewModel)
            }
        }
    }

    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return
        }
        val alreadyGranted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!alreadyGranted) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
