package org.opensecretmanager.app

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

/**
 * The app's process: one device of a vault, in a folder of the app's own,
 * for as long as the process lives. Leaving the app for another one stops
 * taking part and locks the vault, at once or after the time the owner
 * chose ([StayUnlocked]); so does the phone's screen turning off, on a phone
 * with a lock screen, and at once on one without. The screen turning on
 * locks it if that time ran out while the phone slept.
 * Coming back takes part again. While it is closed, it syncs now and then
 * in the background ([BackgroundSync]).
 */
class VaultApp : Application() {
    lateinit var session: VaultSession
        private set

    override fun onCreate() {
        super.onCreate()
        session = VaultSession(this, filesDir.resolve(DEVICE_FOLDER))
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = session.onForeground()
            override fun onStop(owner: LifecycleOwner) = session.onBackground()
        })
        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (intent.action == Intent.ACTION_SCREEN_ON) session.onScreenOn() else session.onScreenOff()
                }
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF).apply { addAction(Intent.ACTION_SCREEN_ON) },
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        BackgroundSync.schedule(this)
    }

    companion object {
        /** Where the vault and the device's other files are kept. */
        const val DEVICE_FOLDER = "vault"
    }
}
