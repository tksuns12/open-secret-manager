package org.opensecretmanager.app.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillContext
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import java.util.concurrent.atomic.AtomicInteger

/**
 * Offers to fill a login form or a one-time code field in another app or a
 * browser, and to save what a login form submitted. It never says what the vault holds: the only offer is
 * "unlock to fill", which opens [FillActivity], where the owner unlocks and
 * chooses the login. A save opens [SaveActivity], where the owner unlocks
 * and chooses where it goes.
 */
class VaultAutofillService : AutofillService() {
    private val requests = AtomicInteger()

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val form = structure?.let(Form::parse)
        if (form == null) {
            // The first screen of a sign-in on two screens offers nothing to
            // fill, but the system keeps what is typed there for the save
            // the next screen asks for.
            val first = structure?.let(Form::usernameScreen)?.takeIf { it.packageName != packageName }
            val delayed = first?.let(::delayedSave)
            callback.onSuccess(delayed?.let { FillResponse.Builder().setSaveInfo(it).build() })
            return
        }
        // Not this app's own screens.
        if (form.packageName == packageName) {
            callback.onSuccess(null)
            return
        }
        val intent = Intent(this, FillActivity::class.java).putExtras(form.toBundle())
        // Mutable: the system adds the screen's structure to it.
        val sender = PendingIntent.getActivity(
            this,
            requests.incrementAndGet(),
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        ).intentSender
        val offer = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "Open Secret Manager · unlock to fill")
        }
        // One entry with no values, locked: choosing it opens the fill
        // screen, whose result fills the form at once.
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(offer).apply {
            listOfNotNull(form.username, form.password, form.oneTimeCode).forEach { setValue(it, null) }
            setAuthentication(sender)
        }.build()
        val response = FillResponse.Builder().addDataset(dataset)
        val usernameEarlier = form.username == null && earlierUsername(request.fillContexts, form) != null
        saveInfo(form, usernameEarlier)?.let(response::setSaveInfo)
        callback.onSuccess(response.build())
    }

    /**
     * For the first screen of a sign-in on two screens: no offer to save
     * there, but the screen kept for the next one's (Android 10 and later).
     */
    private fun delayedSave(first: Form): SaveInfo? {
        if (Build.VERSION.SDK_INT < 29) return null
        val username = first.username ?: return null
        return SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_USERNAME, arrayOf(username))
            .setFlags(SaveInfo.FLAG_DELAY_SAVE)
            .build()
    }

    /**
     * The username field of an earlier screen of the same sign-in, kept by
     * [delayedSave], with the screen as it was read: the latest of the same
     * app and the same site, if any.
     */
    private fun earlierUsername(contexts: List<FillContext>, form: Form): Pair<AssistStructure, AutofillId>? =
        contexts.dropLast(1).asReversed().firstNotNullOfOrNull { context ->
            Form.usernameScreen(context.structure)
                ?.takeIf { it.packageName == form.packageName && it.webDomain == form.webDomain }
                ?.username?.let { context.structure to it }
        }

    /**
     * Asks the system to offer a save once the form is submitted with a
     * password the owner typed (not one this app filled), or once its fields
     * are gone, for apps that hide a form rather than close its screen.
     * [usernameEarlier]: the username was asked for on an earlier screen.
     */
    private fun saveInfo(form: Form, usernameEarlier: Boolean): SaveInfo? {
        val password = form.password ?: return null
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or
            (if (form.username != null || usernameEarlier) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
        return SaveInfo.Builder(type, arrayOf(password)).apply {
            form.username?.let { setOptionalIds(arrayOf(it)) }
            setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
        }.build()
    }

    /**
     * The owner chose to save: the save screen opens, holding what the form
     * submitted in this app's memory only.
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val form = structure?.let(Form::parse)
        if (form == null || form.packageName == packageName) {
            callback.onSuccess()
            return
        }
        val values = Form.values(structure, setOfNotNull(form.username, form.password))
        val password = form.password?.let(values::get).orEmpty()
        // A screen that asked for the password alone: the username, if an
        // earlier screen of the same sign-in asked for it.
        val username = form.username?.let(values::get)
            ?: earlierUsername(request.fillContexts, form)?.let { (screen, id) -> Form.values(screen, setOf(id))[id] }
            ?: ""
        if (password.isEmpty()) {
            callback.onFailure("The form sent no password")
            return
        }
        // Named as the save screen names it, for the app to offer it by if
        // Android does not start that screen.
        val from = when (val requester = Requester.of(this, form)) {
            is Requester.Web -> requester.origin.removePrefix("https://")
            is Requester.App -> requester.label
            null -> form.packageName
        }
        val id = PendingSave.put(PendingSave.Save(form, username, password), from)
        val intent = Intent(this, SaveActivity::class.java).putExtra(SaveActivity.SAVE, id)
        val sender = PendingIntent.getActivity(
            this,
            id,
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        ).intentSender
        callback.onSuccess(sender)
    }
}
