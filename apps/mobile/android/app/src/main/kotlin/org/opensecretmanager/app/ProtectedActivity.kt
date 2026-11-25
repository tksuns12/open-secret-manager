package org.opensecretmanager.app

import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity

/**
 * Common security base for every Activity in Open Secret Manager:
 * - Applies FLAG_SECURE (unless a debug screenshot build explicitly opts out)
 * - Hides non-system overlay windows on API 31+ (`HIDE_OVERLAY_WINDOWS`)
 * - Enables root `filterTouchesWhenObscured` and blocks touches carrying
 *   `FLAG_WINDOW_IS_OBSCURED` or (API 29+) `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`.
 */
abstract class ProtectedActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)
        }
        window.decorView.filterTouchesWhenObscured = true
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (isObscured(ev.flags)) return false
        return super.dispatchTouchEvent(ev)
    }

    companion object {
        internal fun isObscured(flags: Int): Boolean {
            if ((flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) return true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                (flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
            ) {
                return true
            }
            return false
        }
    }
}
