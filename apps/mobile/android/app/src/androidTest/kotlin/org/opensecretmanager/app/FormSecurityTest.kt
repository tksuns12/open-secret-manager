package org.opensecretmanager.app

import android.graphics.RectF
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.opensecretmanager.app.autofill.Form

/**
 * Defensive checks for the autofill field visibility and bounds filters.
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
}
