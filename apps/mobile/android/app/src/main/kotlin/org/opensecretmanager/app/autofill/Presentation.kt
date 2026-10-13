package org.opensecretmanager.app.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.BlendMode
import android.graphics.drawable.Icon
import android.service.autofill.InlinePresentation
import android.view.View
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import org.opensecretmanager.app.MainActivity
import org.opensecretmanager.app.R

/**
 * An entry of the system's list under another app's field: the app's icon,
 * [title], and [subtitle] beneath it if there is one, in colours of its own
 * (`layout/autofill_entry`).
 */
internal fun entry(context: Context, title: String, subtitle: String? = null): RemoteViews =
    RemoteViews(context.packageName, R.layout.autofill_entry).apply {
        setTextViewText(R.id.title, title)
        if (!subtitle.isNullOrEmpty()) {
            setTextViewText(R.id.subtitle, subtitle)
            setViewVisibility(R.id.subtitle, View.VISIBLE)
        }
    }

/**
 * The keyboard's strip, for a keyboard that asks to show a fill's entries
 * there rather than leave them to the system's list (Android 11 and later).
 * The system draws each entry in the keyboard's style, and the keyboard
 * does not learn what it says, only that it is there, until one is chosen.
 */
@RequiresApi(30)
internal class Strip(private val context: Context, private val request: InlineSuggestionsRequest) {
    /** How many entries the keyboard shows. */
    val room: Int get() = request.maxSuggestionCount

    /**
     * The entry at [index] as the keyboard asks for it: the app's icon,
     * [title], and [subtitle] beside it if there is one. Null past [room], or
     * for a style this app cannot draw in; the entry is then in the list.
     */
    fun entry(index: Int, title: String, subtitle: String? = null): InlinePresentation? {
        val specs = request.inlinePresentationSpecs
        if (index >= room || specs.isEmpty()) return null
        // The last spec is for every entry past the others.
        val spec = specs[minOf(index, specs.lastIndex)]
        if (UiVersions.INLINE_UI_VERSION_1 !in UiVersions.getVersions(spec.style)) return null
        // Pressed long, an entry says whose it is, and opens the app.
        val attribution = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        // In its own colours, not tinted as the keyboard's own icons.
        val icon = Icon.createWithResource(context, R.mipmap.ic_launcher).setTintBlendMode(BlendMode.DST)
        val content = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(title)
            .setStartIcon(icon)
            .setContentDescription(listOfNotNull(title, subtitle?.takeIf { it.isNotEmpty() }).joinToString(", "))
        if (!subtitle.isNullOrEmpty()) content.setSubtitle(subtitle)
        return InlinePresentation(slice(content.build()), spec, false)
    }

    // The library's documented way to the slice, which its own annotation
    // marks as internal to it.
    @SuppressLint("RestrictedApi")
    private fun slice(content: InlineSuggestionUi.Content) = content.slice
}
