package org.opensecretmanager.app

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Syncing while the app is closed: now and then (at most every 15 minutes,
 * when the phone is on a network and its battery is not low, as Android
 * decides), the app takes part just long enough to sync with the vault's
 * devices it can reach, and stops. It never unlocks the vault: what this
 * phone wrote goes out, and what arrives waits to be verified at the next
 * unlock. The owner can turn it off in the app; it is on by default.
 */
object BackgroundSync {
    private const val WORK = "background-sync"
    private const val PREFERENCES = "settings"
    private const val KEY = "background-sync"

    fun enabled(context: Context): Boolean =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getBoolean(KEY, true)

    fun set(context: Context, on: Boolean) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit().putBoolean(KEY, on).apply()
        schedule(context)
    }

    /** Asks Android to run it, or not, as the owner set it. */
    fun schedule(context: Context) {
        val work = WorkManager.getInstance(context)
        if (!enabled(context)) {
            work.cancelUniqueWork(WORK)
            return
        }
        val request = PeriodicWorkRequestBuilder<Worker>(15, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build(),
            )
            .build()
        work.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, request)
    }

    /** One sync, run by Android while the app is closed. */
    class Worker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
        override suspend fun doWork(): Result {
            (applicationContext as VaultApp).session.syncInBackground().join()
            return Result.success()
        }
    }
}
