package org.opensecretmanager.app

import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry

/**
 * Joins the desktop-side device whose `invitation` a script passed, through
 * the app's screens: the code shown is logged for the script to compare
 * (`PHONE-CODE`), which answers for the owner on the desktop side; then the
 * phone's password is set, and the desktop's item Mail arrives. Returns the
 * app's session.
 */
@OptIn(ExperimentalTestApi::class)
fun joinTheDesktop(compose: AndroidComposeTestRule<*, *>, invitation: String): VaultSession {
    val session = (InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VaultApp).session
    session.reopenForTests { }
    compose.waitUntilAtLeastOneExists(hasTestTag("invitation"), 30_000)
    compose.onNodeWithTag("invitation").performTextInput(invitation)
    compose.onNodeWithTag("join-continue").performClick()
    compose.waitUntilAtLeastOneExists(hasTestTag("join-code"), 60_000)
    val code = compose.onNodeWithTag("join-code").fetchSemanticsNode()
        .config[SemanticsProperties.Text].joinToString("")
    // The script reads this and compares it with the desktop's.
    Log.i("OSMJoin", "PHONE-CODE $code")
    compose.onNodeWithTag("new-password").performTextInput("phone password, long enough")
    compose.onNodeWithTag("new-password-again").performTextInput("phone password, long enough")
    compose.onNodeWithTag("join-finish").performClick()
    // Joined, unlocked, and the desktop's item arrives as it syncs.
    compose.waitUntilAtLeastOneExists(hasTestTag("item:Mail"), 120_000)
    Log.i("OSMJoin", "PHONE-HAS Mail")
    return session
}

/** Runs a shell command on the device, as the test's instrumentation. */
fun shell(command: String): String {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    return ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
        .bufferedReader().use { it.readText() }
}

/** Waits up to three minutes for `check`. */
fun eventually(what: String, check: () -> Boolean) {
    val deadline = System.currentTimeMillis() + 180_000
    while (!check()) {
        check(System.currentTimeMillis() < deadline) { "never: $what" }
        Thread.sleep(500)
    }
}

/** Waits for a file a script makes in /data/local/tmp, to say it did its part. */
fun waitForScript(file: String, what: String) =
    eventually(what) { shell("ls /data/local/tmp/$file").contains(file) }
