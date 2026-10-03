package org.opensecretmanager.app

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

/**
 * The app's process: one device of a vault, in a folder of the app's own,
 * for as long as the process lives. Leaving the app for another one locks
 * the vault and stops taking part; coming back takes part again.
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
    }

    companion object {
        /** Where the vault and the device's other files are kept. */
        const val DEVICE_FOLDER = "vault"
    }
}
