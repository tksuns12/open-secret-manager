package org.opensecretmanager.app

import android.graphics.Bitmap
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Not a test: captures each screen for a person to look at, in a build made
 * with `-Posm.screenshots=true` and run with the instrumentation argument
 * `screens=true`. The images go to the app's external files folder.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class ScreensForReview {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val session = (instrumentation.targetContext.applicationContext as VaultApp).session

    private fun capture(name: String) {
        compose.waitForIdle()
        Thread.sleep(500)
        val folder = instrumentation.targetContext.getExternalFilesDir("screens")!!
        instrumentation.uiAutomation.takeScreenshot()
            .compress(Bitmap.CompressFormat.PNG, 100, File(folder, "$name.png").outputStream())
    }

    private fun waitFor(tag: String) = compose.waitUntilAtLeastOneExists(hasTestTag(tag), 30_000)

    @Test
    fun captureTheScreens() {
        assumeTrue(BuildConfig.ALLOW_SCREENSHOTS && InstrumentationRegistry.getArguments().getString("screens") == "true")
        session.reopenForTests { }
        waitFor("invitation")
        capture("1-join")
        session.reopenForTests { folder ->
            instrumentation.context.assets.open("format-7-vault.sqlite3").use { input ->
                File(folder, "vault.sqlite3").outputStream().use { output -> input.copyTo(output) }
            }
        }
        waitFor("locked")
        capture("2-locked")
        compose.onNodeWithTag("password").performTextInput("fixture password, not a secret")
        compose.onNodeWithTag("unlock").performClick()
        waitFor("item:Bank")
        capture("3-items")
        compose.onNodeWithTag("item:Bank").performClick()
        waitFor("copy-password")
        capture("4-item")
        compose.onNodeWithTag("copy-password").performClick()
        Thread.sleep(800)
        capture("5-copied")
    }
}
