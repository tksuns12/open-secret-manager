package org.opensecretmanager.app.autofill

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import android.view.accessibility.AccessibilityNodeInfo
import java.lang.ref.WeakReference

/**
 * Fills the other field of a login on a page that tells autofill of one
 * field at a time, as the web view of an app does when the ID and the
 * password are each in a form of their own: Android fills only the fields
 * it was told of, so a login chosen for the ID fills the ID alone. Once the
 * owner turns this on in Android's accessibility settings, a login chosen
 * for one of the two goes into the other too, through Android's
 * accessibility, as typing would: only on a page of an app that is not a
 * browser, where the app is who asks, and not in a browser, trusted or not,
 * whose next page can be another site's.
 *
 * It asks Android for no events and reads no screen until a login is
 * chosen. Then, for a few seconds, it reads the window in front if it is
 * the app that asked, finds there the one password field, or for the
 * username the field before it, and sets that field's text once the system
 * has filled the field that asked. It keeps nothing of what it read, and
 * forgets the value once it is filled or the seconds are up.
 */
class OtherFieldService : AccessibilityService() {
    private val handler = Handler(Looper.getMainLooper())
    private var pending: Pending? = null

    /**
     * [value] for the other field in [packageName]'s window, until
     * [deadline]: the password, or else the username. [filled] is what the
     * system fills into the field that asked, the username when the
     * password waits here.
     */
    private class Pending(val packageName: String, val password: Boolean, val value: String, val filled: String, val deadline: Long) {
        /** When the app's window was first seen in front. */
        var inFront = 0L
        /** Whether the target app was already observed in the foreground. */
        var seenInFront = false
    }

    override fun onServiceConnected() {
        // Read only when a login is chosen: no copy of other screens kept up
        // to date in between (Android 13 and later).
        if (Build.VERSION.SDK_INT >= 33) setCacheEnabled(false)
        running = WeakReference(this)
    }

    override fun onDestroy() {
        if (running?.get() === this) running = null
        handler.removeCallbacksAndMessages(null)
        pending = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}

    override fun onInterrupt() {}

    private fun expect(next: Pending) {
        handler.post {
            handler.removeCallbacksAndMessages(null)
            pending = next
            look()
        }
    }

    private fun clearPending() {
        handler.post {
            handler.removeCallbacksAndMessages(null)
            pending = null
        }
    }

    private fun look() {
        val wanted = pending ?: return
        val now = SystemClock.elapsedRealtime()
        if (now > wanted.deadline) {
            pending = null
            return
        }
        // The fill screen goes first, and the app that asked comes back.
        val root = rootInActiveWindow
        val activePackage = root?.packageName?.toString()
        if (root != null && activePackage == wanted.packageName) {
            if (wanted.inFront == 0L) wanted.inFront = now
            wanted.seenInFront = true
            if (fill(root, wanted, settled = now - wanted.inFront >= SETTLE_MILLIS)) {
                pending = null
                return
            }
        } else if (wanted.seenInFront && activePackage != null && activePackage != wanted.packageName) {
            // The target app left the foreground: cancel immediately so the
            // secret is never injected if the user switches back later.
            pending = null
            return
        }
        handler.postDelayed(::look, POLL_MILLIS)
    }

    /**
     * Fills the other field once the companion field that asked is confirmed
     * filled. Password injection never falls back to a blind time delay: the
     * companion username filled by the system must be present in the same
     * window. False if not filled yet.
     */
    private fun fill(root: AccessibilityNodeInfo, wanted: Pending, settled: Boolean): Boolean {
        val fields = fields(root)
        // One password field, as a login page has; on any other page,
        // nothing is filled.
        val password = fields.filter { it.isPassword }.singleOrNull() ?: return false
        val target: AccessibilityNodeInfo
        val ready: Boolean
        if (wanted.password) {
            target = password
            ready = wanted.filled.isNotEmpty() && fields.any { !it.isPassword && shown(it) == wanted.filled }
        } else {
            // The field nearest before the password that is named a username,
            // or else the one just before it, as for a screen's fields ([Form]).
            val before = fields.take(fields.indexOf(password)).filter { !it.isPassword && !Form.namesOtherThanUsername(names(it)) }
            target = before.lastOrNull { Form.namesUsername(names(it)) } ?: before.lastOrNull() ?: return false
            ready = settled || shown(password).isNotEmpty()
        }
        if (!ready) return false
        val text = Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, wanted.value) }
        return target.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, text)
    }

    /** The editable fields shown, in the order of the window's tree. */
    private fun fields(root: AccessibilityNodeInfo): List<AccessibilityNodeInfo> {
        val found = mutableListOf<AccessibilityNodeInfo>()
        var visited = 0
        fun visit(node: AccessibilityNodeInfo) {
            if (++visited > MAX_NODES) return
            if (node.isEditable && node.isVisibleToUser) found += node
            for (index in 0 until node.childCount) node.getChild(index)?.let(::visit)
        }
        visit(root)
        return found
    }

    /** What a field shows, but for its placeholder. */
    private fun shown(field: AccessibilityNodeInfo): String =
        if (field.isShowingHintText) "" else field.text?.toString().orEmpty()

    private fun names(field: AccessibilityNodeInfo): List<String> =
        listOfNotNull(field.viewIdResourceName, field.hintText?.toString())

    companion object {
        /** How long after a login is chosen the other field may be filled. */
        private const val DEADLINE_MILLIS = 4_000L

        /** How long the app's window is in front before the field that asked is taken to be filled. */
        private const val SETTLE_MILLIS = 800L
        private const val POLL_MILLIS = 150L

        /** The most views read of a window: a login page has far fewer. */
        private const val MAX_NODES = 3_000

        private var running: WeakReference<OtherFieldService>? = null

        /** For tests: whether Android has started the service. */
        internal val connectedForTests: Boolean
            get() = running?.get() != null

        /** Whether the owner turned it on in Android's accessibility settings. */
        fun enabled(context: Context): Boolean =
            context.getSystemService(AccessibilityManager::class.java)
                ?.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .orEmpty()
                .any { it.resolveInfo.serviceInfo.let { service -> service.packageName == context.packageName && service.name == OtherFieldService::class.java.name } }

        /**
         * Once the system fills [filled] into the field that asked in
         * [packageName]'s window, [value] goes into the other: the
         * [password] field, or else the username's. Nothing, unless the
         * owner turned this on.
         */
        fun fillAfter(packageName: String, password: Boolean, value: String, filled: String) {
            val service = running?.get() ?: return
            service.expect(Pending(packageName, password, value, filled, SystemClock.elapsedRealtime() + DEADLINE_MILLIS))
        }

        /** Discards any pending accessibility fill immediately (thread-safe). */
        fun cancel() {
            running?.get()?.clearPending()
        }
    }
}
