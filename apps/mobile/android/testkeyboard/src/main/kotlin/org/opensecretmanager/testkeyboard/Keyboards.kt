package org.opensecretmanager.testkeyboard

import android.annotation.TargetApi
import android.graphics.Color
import android.inputmethodservice.InputMethodService
import android.os.Bundle
import android.util.Size
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.InlineSuggestionsRequest
import android.view.inputmethod.InlineSuggestionsResponse
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi

/**
 * Keyboards for the autofill tests, so that what the system shows does not
 * depend on the phone's own keyboard and its settings. Neither has keys:
 * the tests type with `input text`, whose keys a keyboard passes on.
 */
open class PlainKeyboard : InputMethodService() {
    protected open val name = "Plain keyboard"

    /** What the keyboard shows: a band with its name, the height of a keyboard. */
    protected fun band(): View = TextView(this).apply {
        text = name
        setBackgroundColor(Color.LTGRAY)
        height = (240 * resources.displayMetrics.density).toInt()
    }

    override fun onCreateInputView(): View = band()

    // Shown whenever a field takes the focus, as a phone's keyboard is,
    // though the emulator has keys of its own.
    override fun onEvaluateInputViewShown(): Boolean {
        super.onEvaluateInputViewShown()
        return true
    }
}

/**
 * A keyboard that asks for a fill's entries in its strip, as Gboard and
 * Samsung's keyboard can, and shows them there side by side, above its
 * band. The tests find the strip by its description, [STRIP].
 */
@TargetApi(30)
class StripKeyboard : PlainKeyboard() {
    override val name = "Strip keyboard"
    private lateinit var strip: LinearLayout
    private var responses = 0

    override fun onCreate() {
        super.onCreate()
        strip = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            contentDescription = STRIP
            minimumHeight = (48 * resources.displayMetrics.density).toInt()
        }
    }

    override fun onCreateInputView(): View {
        (strip.parent as? ViewGroup)?.removeView(strip)
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(strip)
            addView(band())
        }
    }

    override fun onCreateInlineSuggestionsRequest(uiExtras: Bundle): InlineSuggestionsRequest {
        val style = UiVersions.newStylesBuilder().addStyle(InlineSuggestionUi.newStyleBuilder().build()).build()
        val density = resources.displayMetrics.density
        val spec = InlinePresentationSpec.Builder(
            Size((96 * density).toInt(), (40 * density).toInt()),
            Size((320 * density).toInt(), (48 * density).toInt()),
        ).setStyle(style).build()
        return InlineSuggestionsRequest.Builder(listOf(spec)).build()
    }

    override fun onInlineSuggestionsResponse(response: InlineSuggestionsResponse): Boolean {
        strip.removeAllViews()
        val suggestions = response.inlineSuggestions
        // Put in the strip in the order given, once each is drawn, unless
        // another response came meanwhile.
        val current = ++responses
        val drawn = arrayOfNulls<View>(suggestions.size)
        var left = suggestions.size
        val size = Size(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        suggestions.forEachIndexed { index, suggestion ->
            suggestion.inflate(this, size, mainExecutor) { view ->
                if (current != responses) return@inflate
                drawn[index] = view
                left -= 1
                if (left == 0) drawn.filterNotNull().forEach(strip::addView)
            }
        }
        return true
    }

    companion object {
        const val STRIP = "Fill entries"
    }
}
