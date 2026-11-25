package org.opensecretmanager.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock

/**
 * Copies a secret for pasting elsewhere. It is marked sensitive, so the
 * system does not show it in its preview of what was copied, and it comes
 * off the clipboard after 30 seconds (tracked against monotonic
 * [SystemClock.elapsedRealtime] so Doze/sleep cannot extend its lifetime).
 *
 * Android lets an app read the clipboard only while it is in front, so
 * whether something else was copied since can be checked only then. If
 * the app is in the background by then, as it is after the owner switched
 * to paste, the clipboard is cleared anyway: a password left there is the
 * larger risk than something copied in the meantime.
 */
object SecretClipboard {
    private const val CLEAR_AFTER_MS = 30_000L
    private val handler = Handler(Looper.getMainLooper())
    private var clearTask: Runnable? = null
    private var clearAtElapsed: Long = 0L
    private var copiedAt: Long? = null

    @Synchronized
    fun copy(context: Context, label: String, text: String, secret: Boolean) {
        val appContext = context.applicationContext
        val clipboard = appContext.getSystemService(ClipboardManager::class.java)
        clearTask?.let { handler.removeCallbacks(it) }
        clearTask = null
        clearAtElapsed = 0L
        copiedAt = null

        val clip = ClipData.newPlainText(label, text)
        if (secret) {
            clip.description.extras = PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= 33) {
                    ClipDescription.EXTRA_IS_SENSITIVE
                } else {
                    "android.content.extra.IS_SENSITIVE"
                }
                putBoolean(key, true)
            }
        }
        clipboard.setPrimaryClip(clip)
        if (!secret) return
        val timestamp = clipboard.primaryClipDescription?.timestamp
        copiedAt = timestamp
        clearAtElapsed = SystemClock.elapsedRealtime() + CLEAR_AFTER_MS
        val task = Runnable {
            synchronized(this) {
                clearInternal(appContext, timestamp)
            }
        }
        clearTask = task
        handler.postDelayed(task, CLEAR_AFTER_MS)
    }

    /** Clears any tracked secret clipboard entry immediately (explicit lock or screen off). */
    @Synchronized
    fun clearNow(context: Context) {
        clearTask?.let { handler.removeCallbacks(it) }
        clearTask = null
        if (clearAtElapsed == 0L) return
        clearInternal(context.applicationContext, copiedAt)
    }

    /** Clears the clipboard if the secret expiry deadline passed while the device slept. */
    @Synchronized
    fun clearIfDue(context: Context) {
        if (clearAtElapsed == 0L || SystemClock.elapsedRealtime() < clearAtElapsed) return
        clearTask?.let { handler.removeCallbacks(it) }
        clearTask = null
        clearInternal(context.applicationContext, copiedAt)
    }

    private fun clearInternal(appContext: Context, expectedAt: Long?) {
        clearTask = null
        clearAtElapsed = 0L
        copiedAt = null
        val clipboard = appContext.getSystemService(ClipboardManager::class.java) ?: return
        val now = clipboard.primaryClipDescription
        if (now == null || expectedAt == null || now.timestamp == expectedAt) {
            clipboard.clearPrimaryClip()
        }
    }
}
