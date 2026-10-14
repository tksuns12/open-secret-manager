package org.opensecretmanager.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Random
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The scanner's reading of a QR code, without a camera: the code the desktop
 * draws for the frozen invitation (`apps/desktop/src-tauri/fixtures/
 * invitation-qr.txt`, rows of `#` for dark and `.` for light, its border
 * included) read back from frames made of it, as a camera might give them.
 */
@RunWith(AndroidJUnit4::class)
class QrDecodeTest {
    private val assets = InstrumentationRegistry.getInstrumentation().context.assets
    private val grid = assets.open("invitation-qr.txt").bufferedReader().readLines().filter { it.isNotEmpty() }
    private val invitation =
        JSONObject(assets.open("pairing.json").bufferedReader().readText()).getString("invitation_text")

    /** A frame's brightness values, `rowWidth` bytes a row. */
    private class Frame(val bytes: ByteArray, val rowWidth: Int, val width: Int, val height: Int)

    /**
     * The grid drawn at `scale` pixels a module inside `margin` pixels of
     * grey, as the camera sees the screen and what is around it; `turned`
     * a quarter turn, as a sensor gives it; each pixel off by up to `noise`;
     * and each row padded to `rowWidth` as a camera's buffer may be.
     */
    private fun frame(scale: Int, margin: Int, turned: Boolean = false, noise: Int = 0, padding: Int = 0): Frame {
        val modules = grid.size
        val side = modules * scale + 2 * margin
        val rowWidth = side + padding
        val bytes = ByteArray(rowWidth * side)
        val random = Random(7)
        for (y in 0 until side) {
            for (x in 0 until side) {
                val (column, row) = (x - margin) / scale to (y - margin) / scale
                val inside = x >= margin && y >= margin && column < modules && row < modules
                val dark = inside && (if (turned) grid[modules - 1 - column][row] else grid[row][column]) == '#'
                val value = (if (!inside) 128 else if (dark) 30 else 225) + if (noise > 0) random.nextInt(2 * noise + 1) - noise else 0
                bytes[y * rowWidth + x] = value.coerceIn(0, 255).toByte()
            }
        }
        return Frame(bytes, rowWidth, side, side)
    }

    private fun read(frame: Frame) = decodeQr(frame.bytes, frame.rowWidth, frame.width, frame.height)

    @Test
    fun theDesktopsCodeOfTheFrozenInvitationReadsBackAsTheInvitationItself() {
        assertEquals(73, grid.size)
        assertEquals(invitation, read(frame(scale = 4, margin = 40)))
        assertEquals(invitation, read(frame(scale = 4, margin = 40, turned = true)))
        assertEquals(invitation, read(frame(scale = 3, margin = 60, noise = 40)))
        assertEquals(invitation, read(frame(scale = 4, margin = 20, padding = 32)))
    }

    @Test
    fun aFrameWithNoCodeReadsAsNothing() {
        val random = Random(11)
        val bytes = ByteArray(320 * 240).also(random::nextBytes)
        assertNull(decodeQr(bytes, 320, 320, 240))
        assertNull(decodeQr(ByteArray(320 * 240) { 128.toByte() }, 320, 320, 240))
    }
}
