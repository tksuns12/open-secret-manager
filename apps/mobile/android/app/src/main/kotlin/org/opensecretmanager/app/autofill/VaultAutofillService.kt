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
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import java.util.concurrent.atomic.AtomicInteger
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.cardLine
import org.opensecretmanager.vault.ItemSummary

/**
 * Offers to fill a login form, a username field alone, a one-time code
 * field, or a card form in another app or a browser, and to save what a
 * login form submitted. While the vault is locked it says nothing of what the vault
 * holds: the only offer is "unlock to fill", which opens [FillActivity],
 * where the owner unlocks and chooses the login. While it is unlocked (for a
 * while after the app or a fill screen was left, see
 * [org.opensecretmanager.app.StayUnlocked]), the system's list names the
 * logins a fill would offer, by title and username, and choosing one fills
 * it at once. A keyboard that asks for them gets the same entries in its
 * strip, and the system's list is not shown (see [Strip]). A save opens
 * [SaveActivity], where the owner unlocks and chooses where it goes. A
 * sign-up's or a change of password's form is also offered, first, "make a
 * strong password", locked or not, which opens [GenerateActivity].
 */
class VaultAutofillService : AutofillService() {
    private val requests = AtomicInteger()

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        // A screen with a username field and no password field is offered
        // the username alone: the first screen of a sign-in on two screens,
        // or a page whose fields are each in a form of their own, which a web
        // view reports one at a time; the password then goes into the
        // page's own field through OtherFieldService, if the owner turned it
        // on. The system keeps what is typed there for the save the
        // password's screen asks for.
        val form = structure?.let { Form.parse(it) ?: Form.usernameScreen(it) }
        // A card form, or a card's field on a screen with a login form too.
        val card = structure?.let(CardForm::parse)
        if (card != null && card.packageName != packageName && (form == null || card.focused)) {
            offerCards(request, card, callback)
            return
        }
        if (form == null) {
            callback.onSuccess(null)
            return
        }
        // Not this app's own screens.
        if (form.packageName == packageName) {
            callback.onSuccess(null)
            return
        }
        val usernameEarlier = form.username == null && earlierUsername(request.fillContexts, form) != null
        val requester = Requester.of(this, form)
        val codeOnly = form.codeOnly
        val strip = if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest?.let { Strip(this, it) } else null
        val respond = { logins: List<ItemSummary>? ->
            val response = FillResponse.Builder()
            val offers = mutableListOf<Dataset>()
            // The same entry in the list and, if the keyboard asks, in its
            // strip, where the app's icon names the app and a short title
            // ([inStrip]) is not cut off.
            val add = { title: String, subtitle: String?, inStrip: String, item: String? ->
                val inline = if (Build.VERSION.SDK_INT >= 30) strip?.entry(offers.size, inStrip, subtitle) else null
                offers += offer(form, entry(this, title, subtitle), inline, item)
            }
            // A password made for a new account or a change of password: it
            // tells nothing of the vault, so it is offered locked too.
            val generating = form.newPasswords.isNotEmpty()
            if (generating) {
                val inline = if (Build.VERSION.SDK_INT >= 30) strip?.entry(offers.size, "Make a strong password") else null
                offers += generateOffer(form, entry(this, "Open Secret Manager · make a strong password"), inline)
            }
            if (logins == null) {
                add("Open Secret Manager · unlock to fill", null, "Unlock to fill", null)
            } else {
                // Room left in the strip for the last entry, and the one to make a password.
                val kept = if (generating) 2 else 1
                val listed = if (Build.VERSION.SDK_INT >= 30 && strip != null) minOf(MAX_LOGINS, strip.room - kept) else MAX_LOGINS
                logins.take(listed.coerceAtLeast(0)).forEach { add(it.title, it.username, it.title, it.id) }
                // The fill screen, for the rest, or for choosing a login for an app.
                val (more, inStrip) = when {
                    logins.isNotEmpty() -> "Open Secret Manager…" to "Open Secret Manager…"
                    requester is Requester.App -> "Open Secret Manager · choose a login…" to "Choose a login…"
                    codeOnly -> "Open Secret Manager · no code for this site" to "No code for this site"
                    else -> "Open Secret Manager · no login for this site" to "No login for this site"
                }
                add(more, null, inStrip, null)
            }
            offers.forEach(response::addDataset)
            (saveInfo(form, usernameEarlier) ?: delayedSave(form))?.let(response::setSaveInfo)
            callback.onSuccess(response.build())
        }
        // What a fill would offer, if the vault is unlocked.
        when (requester) {
            null -> respond(null)
            is Requester.Web -> session().offered(requester.origin, emptySet(), codeOnly, respond)
            is Requester.App -> session().offered(null, AppLogins(this).chosen(requester), codeOnly, respond)
        }
    }

    private fun session() = (application as VaultApp).session

    /**
     * An entry with no values, locked: choosing it opens the fill screen,
     * whose result fills the form at once. With [item], the login chosen in
     * the list, which the screen fills without showing itself if the vault
     * is still unlocked. [inline]: the entry for the keyboard's strip, if it
     * has one.
     */
    private fun offer(form: Form, presentation: RemoteViews, inline: InlinePresentation?, item: String?): Dataset {
        val intent = Intent(this, FillActivity::class.java).putExtras(form.toBundle())
        item?.let { intent.putExtra(FillActivity.ITEM, it) }
        // Mutable: the system adds the screen's structure to it.
        val sender = PendingIntent.getActivity(
            this,
            requests.incrementAndGet(),
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        ).intentSender
        @Suppress("DEPRECATION")
        return Dataset.Builder(presentation).apply {
            listOfNotNull(form.username, form.password, form.oneTimeCode).forEach { setValue(it, null) }
            if (inline != null && Build.VERSION.SDK_INT >= 30) setInlinePresentation(inline)
            setAuthentication(sender)
        }.build()
    }

    /**
     * The entry that makes a password for [form]'s new password fields:
     * [GenerateActivity], which saves it and fills it. It names the new
     * fields and the username, so that it is offered on each.
     */
    private fun generateOffer(form: Form, presentation: RemoteViews, inline: InlinePresentation?): Dataset {
        val intent = Intent(this, GenerateActivity::class.java).putExtras(form.toBundle())
        // Mutable: the system adds the screen's structure to it.
        val sender = PendingIntent.getActivity(
            this,
            requests.incrementAndGet(),
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        ).intentSender
        @Suppress("DEPRECATION")
        return Dataset.Builder(presentation).apply {
            (listOfNotNull(form.username) + form.newPasswords).forEach { setValue(it, null) }
            if (inline != null && Build.VERSION.SDK_INT >= 30) setInlinePresentation(inline)
            setAuthentication(sender)
        }.build()
    }

    /**
     * Offers the cards for a card form: while locked, "unlock to fill a
     * card"; while unlocked, every card by its title, brand, and the last
     * four digits of its number, as a card belongs to no site, and the fill
     * screen ([CardFillActivity]) for the rest. Nothing is offered to save.
     */
    private fun offerCards(request: FillRequest, card: CardForm, callback: FillCallback) {
        val strip = if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest?.let { Strip(this, it) } else null
        session().offeredCards { cards ->
            val response = FillResponse.Builder()
            val offers = mutableListOf<Dataset>()
            val add = { title: String, subtitle: String?, inStrip: String, item: String? ->
                val inline = if (Build.VERSION.SDK_INT >= 30) strip?.entry(offers.size, inStrip, subtitle) else null
                offers += cardOffer(card, entry(this, title, subtitle), inline, item)
            }
            if (cards == null) {
                add("Open Secret Manager · unlock to fill a card", null, "Unlock to fill", null)
            } else {
                val listed = if (Build.VERSION.SDK_INT >= 30 && strip != null) minOf(MAX_LOGINS, strip.room - 1) else MAX_LOGINS
                cards.take(listed.coerceAtLeast(0)).forEach { add(it.title, cardLine(it.brand, it.cardEnding), it.title, it.id) }
                if (cards.isEmpty()) add("Open Secret Manager · no card saved", null, "No card saved", null)
                else add("Open Secret Manager…", null, "Open Secret Manager…", null)
            }
            offers.forEach(response::addDataset)
            callback.onSuccess(response.build())
        }
    }

    /** As [offer], for a card form: the card chosen in the list is [item]. */
    private fun cardOffer(card: CardForm, presentation: RemoteViews, inline: InlinePresentation?, item: String?): Dataset {
        val intent = Intent(this, CardFillActivity::class.java).putExtras(card.toBundle())
        item?.let { intent.putExtra(CardFillActivity.ITEM, it) }
        val sender = PendingIntent.getActivity(
            this,
            requests.incrementAndGet(),
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        ).intentSender
        @Suppress("DEPRECATION")
        return Dataset.Builder(presentation).apply {
            card.fields.forEach { setValue(it.id, null) }
            if (inline != null && Build.VERSION.SDK_INT >= 30) setInlinePresentation(inline)
            setAuthentication(sender)
        }.build()
    }

    /**
     * For a screen with a username field and no password field: no offer to
     * save there, but the screen kept for the next one's (Android 10 and
     * later).
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
     * On a change of password, the new password is the one saved.
     */
    private fun saveInfo(form: Form, usernameEarlier: Boolean): SaveInfo? {
        val password = form.newPasswords.firstOrNull() ?: form.password ?: return null
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
        val sent = form.newPasswords.firstOrNull() ?: form.password
        val values = Form.values(structure, setOfNotNull(form.username, sent))
        val password = sent?.let(values::get).orEmpty()
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

    private companion object {
        /** The most logins the list names; the fill screen has the rest. */
        const val MAX_LOGINS = 10
    }
}
