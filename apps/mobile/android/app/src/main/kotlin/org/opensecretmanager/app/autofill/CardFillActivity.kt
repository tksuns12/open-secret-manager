package org.opensecretmanager.app.autofill

import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import org.opensecretmanager.app.BiometricUnlock
import org.opensecretmanager.app.BuildConfig
import org.opensecretmanager.app.Busy
import org.opensecretmanager.app.FingerprintPrompts
import org.opensecretmanager.app.Message
import org.opensecretmanager.app.Screen
import org.opensecretmanager.app.Unlock
import org.opensecretmanager.app.VaultApp
import org.opensecretmanager.app.VaultSession
import org.opensecretmanager.app.cardLine
import org.opensecretmanager.app.screenState
import org.opensecretmanager.vault.CardFill
import org.opensecretmanager.vault.ItemKind
import org.opensecretmanager.vault.ItemSummary

/**
 * Where the owner fills a card into a card form of another app or a page,
 * after choosing "unlock to fill a card" in it: unlock, see who asks and
 * what the form asks for, choose the card. A card belongs to no site, so
 * every card is offered, to any app or page; nothing is remembered for an
 * app, and the owner chooses each time. A card the owner chose in the
 * system's list while the vault was unlocked ([ITEM]) is filled without
 * this screen showing, or once unlocked if the vault locked meanwhile.
 * Once this screen goes, the vault locks as when the app is left.
 */
class CardFillActivity : FragmentActivity() {
    private lateinit var form: CardForm

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.ALLOW_SCREENSHOTS) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setResult(RESULT_CANCELED)
        form = intent.extras?.let(CardForm::fromBundle) ?: return finish()
        val session = (application as VaultApp).session
        if (savedInstanceState == null) session.askAtOnceNext()
        val requester = Requester.of(this, form)
        val chosen = intent.getStringExtra(ITEM)
        if (chosen == null || requester == null) return show(session, requester, null)
        // Nothing drawn while it fills: the app that asked stays in sight.
        val background = window.decorView.background
        window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
        session.fillCardChosen(chosen) { card ->
            if (card != null) {
                finishWith(card)
            } else {
                window.setBackgroundDrawable(background)
                show(session, requester, chosen)
            }
        }
    }

    private fun show(session: VaultSession, requester: Requester?, chosen: String?) {
        val biometric = BiometricUnlock(this)
        val prompts = FingerprintPrompts(this, biometric, session, requester?.said)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                CardFillScreen(form, requester, chosen, session, biometric, prompts, onFill = ::finishWith, onCancel = ::finish)
            }
        }
    }

    /** Hands the card to the form that asked, which fills it at once. */
    private fun finishWith(card: CardFill) {
        val values = form.values(card)
        if (values.isEmpty()) return finish()
        val presentation = entry(this, getString(org.opensecretmanager.app.R.string.app_name))
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(presentation).apply {
            values.forEach { (id, value) -> setValue(id, value) }
        }.build()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        finish()
    }

    companion object {
        /** The extra naming the card the owner chose in the system's list. */
        const val ITEM = "item"
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
private fun CardFillScreen(
    form: CardForm,
    requester: Requester?,
    chosen: String?,
    session: VaultSession,
    biometric: BiometricUnlock,
    prompts: FingerprintPrompts,
    onFill: (CardFill) -> Unit,
    onCancel: () -> Unit,
) {
    val state by session.screenState()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.notice) {
        state.notice?.let {
            snackbar.showSnackbar(it)
            session.dismissNotice()
        }
    }
    // A card chosen in the system's list, the vault locked meanwhile: filled
    // once it is unlocked.
    var pending by remember { mutableStateOf(chosen) }
    LaunchedEffect(state.screen, pending) {
        val item = pending ?: return@LaunchedEffect
        if (state.screen != Screen.UNLOCKED || requester == null) return@LaunchedEffect
        pending = null
        session.fillCard(item, onFill)
    }
    Scaffold(
        // Tags as resource ids: the tests drive this screen from outside the
        // app, as the system shows it over another one.
        modifier = Modifier.semantics { testTagsAsResourceId = true },
        topBar = {
            TopAppBar(
                title = { Text("Fill a card") },
                actions = { TextButton(onClick = onCancel, modifier = Modifier.testTag("cancel")) { Text("Cancel") } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when {
                requester == null -> Message(
                    "Nothing to fill",
                    "Open Secret Manager cannot tell which app asks, so it fills nothing.",
                )
                state.screen == Screen.OPENING -> Message("Opening…")
                state.screen == Screen.LOCKED -> Column {
                    Asker(requester)
                    Unlock(state, session, biometric, prompts::unlock, prompts::keep)
                }
                state.screen == Screen.UNLOCKED -> Column {
                    Asker(requester)
                    Asks(form)
                    CardRows(state.items.filter { it.kind == ItemKind.CARD && !it.conflict }.sortedBy { it.title.lowercase() }) {
                        session.fillCard(it.id, onFill)
                    }
                }
                state.screen == Screen.REMOVED -> Message("This phone was removed from the vault")
                state.screen == Screen.UNREADABLE -> Message("The vault on this phone cannot be opened", state.unreadable)
                else -> Message("This phone has no vault yet", "Join your vault in Open Secret Manager first.")
            }
            state.busy?.let { Busy(it) }
        }
    }
}

/** What of a card the form takes, which goes to whoever [Asker] names. */
@Composable
private fun Asks(form: CardForm) {
    Text(
        "This form asks for the card's " + form.asks.joinToString(", ") { it.said } +
            ". A card is offered to any app or page that asks: choose one only if this is where you mean to pay.",
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp).testTag("card-asks"),
    )
}

@Composable
private fun CardRows(cards: List<ItemSummary>, onChoose: (ItemSummary) -> Unit) {
    if (cards.isEmpty()) {
        Column(Modifier.padding(24.dp)) {
            Text("No card saved", style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("no-cards"))
            Text("Add a card in Open Secret Manager, or on your computer.", style = MaterialTheme.typography.bodyMedium)
        }
        return
    }
    LazyColumn(Modifier.padding(horizontal = 24.dp)) {
        items(cards, key = { it.id }) { card ->
            Column(Modifier.fillMaxWidth().clickable { onChoose(card) }.padding(vertical = 12.dp).testTag("fill:${card.title}")) {
                Text(card.title, style = MaterialTheme.typography.titleMedium)
                Text(cardLine(card.brand, card.cardEnding), style = MaterialTheme.typography.bodySmall)
            }
            HorizontalDivider()
        }
    }
}
