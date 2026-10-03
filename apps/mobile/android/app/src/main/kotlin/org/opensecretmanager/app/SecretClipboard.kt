package org.opensecretmanager.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies a secret for pasting elsewhere. It is marked sensitive, so the
 * system does not show it in its preview of what was copied, and it comes
 * off the clipboard after 30 seconds.
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

    fun copy(context: Context, label: String, text: String, secret: Boolean) {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
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
        val copiedAt = clipboard.primaryClipDescription?.timestamp
        handler.postDelayed({
            val now = clipboard.primaryClipDescription
            if (now == null || now.timestamp == copiedAt) {
                clipboard.clearPrimaryClip()
            }
        }, CLEAR_AFTER_MS)
    }
}
