package org.opensecretmanager.app.autofill

import android.content.Context
import android.view.View
import android.widget.RemoteViews
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
