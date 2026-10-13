package org.opensecretmanager.app

/**
 * The phone's keyboard during an autofill test: one of the test keyboards
 * (`testkeyboard`'s `Keyboards.kt`), so that where the system shows a
 * fill's entries does not depend on the phone's own keyboard and its
 * settings. [putBack] restores the keyboard there was, never a test one,
 * which a run stopped before it put the keyboard back would have left.
 */
internal class Keyboard(private val shell: (String) -> String) {
    private var previous: String? = null
    private var saved = false

    /** Makes the test keyboard [name] the phone's: `PlainKeyboard` or `StripKeyboard`. */
    fun use(name: String) {
        if (!saved) {
            previous = current().takeIf { it.isNotEmpty() && it != "null" && !it.startsWith("$PACKAGE/") }
            saved = true
        }
        val id = "$PACKAGE/.$name"
        shell("ime enable $id")
        shell("ime set $id")
        val deadline = System.currentTimeMillis() + 10_000
        while (current() != id && System.currentTimeMillis() < deadline) Thread.sleep(100)
        if (current() != id) throw AssertionError("the keyboard is ${current()}, not $id")
    }

    fun putBack() {
        if (!saved) return
        shell(previous?.let { "ime set $it" } ?: "ime reset")
        KEYBOARDS.forEach { shell("ime disable $PACKAGE/.$it") }
        saved = false
    }

    private fun current() = shell("settings get secure default_input_method").trim()

    companion object {
        const val PACKAGE = "org.opensecretmanager.testkeyboard"
        val KEYBOARDS = listOf("PlainKeyboard", "StripKeyboard")

        /** The description of the strip keyboard's strip. */
        const val STRIP = "Fill entries"
    }
}
