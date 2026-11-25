package org.opensecretmanager.app

import android.graphics.RectF
import android.os.Build
import android.view.MotionEvent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Form
import org.opensecretmanager.app.autofill.Requester
import org.opensecretmanager.app.passkey.PasskeyAsker
import org.opensecretmanager.vault.PasskeyCaller

/**
 * Defensive checks for autofill field visibility, trusted browser fail-closed
 * origin checks, tapjacking flags, and exact passkey DAL matching.
 */
@RunWith(AndroidJUnit4::class)
class FormSecurityTest {
    @Test
    fun visibleBoundsRejectsTinyAndOffScreenFields() {
        val windowWidth = 1080
        // Normal on-screen input field.
        assertTrue(Form.isVisibleBounds(RectF(24f, 120f, 960f, 200f), windowWidth))
        // Vertically scrolled below the fold is still allowed.
        assertTrue(Form.isVisibleBounds(RectF(24f, 2400f, 960f, 2480f), windowWidth))
        // Zero-size and 1x1 / 3x3 pixel decoy fields are rejected.
        assertFalse(Form.isVisibleBounds(RectF(10f, 10f, 10f, 10f), windowWidth))
        assertFalse(Form.isVisibleBounds(RectF(10f, 10f, 11f, 11f), windowWidth))
        assertFalse(Form.isVisibleBounds(RectF(10f, 10f, 13f, 50f), windowWidth))
        assertFalse(Form.isVisibleBounds(RectF(10f, 10f, 100f, 13f), windowWidth))
        // Off-screen negative left, negative top, and past right edge are rejected.
        assertFalse(Form.isVisibleBounds(RectF(-9999f, 20f, -9899f, 70f), windowWidth))
        assertFalse(Form.isVisibleBounds(RectF(20f, -9999f, 200f, -9949f), windowWidth))
        assertFalse(Form.isVisibleBounds(RectF(1080f, 20f, 1280f, 70f), windowWidth))
        assertFalse(Form.isVisibleBounds(RectF(9999f, 20f, 10199f, 70f), windowWidth))
    }

    @Test
    fun trustedBrowserWithoutHttpsDomainIsRefused() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val pkg = context.packageName
        Requester.trustedForTests += pkg
        try {
            assertNull(Requester.of(context, pkg, null, null))
            assertNull(Requester.of(context, pkg, "", "https"))
            assertNull(Requester.of(context, pkg, "example.test", null))
            assertNull(Requester.of(context, pkg, "example.test", "http"))
            val web = Requester.of(context, pkg, "Example.Test", "https")
            assertTrue(web is Requester.Web)
            assertEquals("https://example.test", (web as Requester.Web).origin)
        } finally {
            Requester.trustedForTests.clear()
        }
    }

    @Test
    fun protectedActivityRejectsObscuredMotionEvents() {
        assertFalse(ProtectedActivity.isObscured(0))
        assertTrue(ProtectedActivity.isObscured(MotionEvent.FLAG_WINDOW_IS_OBSCURED))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            assertTrue(ProtectedActivity.isObscured(MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED))
        }
    }

    @Test
    fun passkeyAskerLinkedToRequiresExactHostMatch() {
        val asker = PasskeyAsker(
            Requester.App("org.example.app", "Example", "AA", null),
            PasskeyCaller.App(byteArrayOf(1)),
            setOf("app.example.test", "exact.test"),
        )
        assertTrue(asker.linkedTo("exact.test"))
        assertTrue(asker.linkedTo("EXACT.TEST"))
        assertTrue(asker.linkedTo("app.example.test"))
        assertFalse(asker.linkedTo("example.test"))
        assertFalse(asker.linkedTo("sub.exact.test"))
        assertFalse(asker.linkedTo("www.exact.test"))
        assertFalse(asker.linkedTo(""))
    }

    @Test
    fun hiddenInlineStyleRejectsLowOpacityDisplayNoneAndVisibilityHidden() {
        assertTrue(Form.isHiddenInlineStyle("opacity: 0.01"))
        assertTrue(Form.isHiddenInlineStyle("color: red; opacity: 0;"))
        assertTrue(Form.isHiddenInlineStyle("opacity: 5% !important"))
        assertTrue(Form.isHiddenInlineStyle("display: none"))
        assertTrue(Form.isHiddenInlineStyle("visibility: hidden"))
        assertTrue(Form.isHiddenInlineStyle("visibility: collapse"))
        assertFalse(Form.isHiddenInlineStyle("opacity: 0.5"))
        assertFalse(Form.isHiddenInlineStyle("opacity: 1"))
        assertFalse(Form.isHiddenInlineStyle("display: block; visibility: visible"))
        assertFalse(Form.isHiddenInlineStyle(""))
    }
}
