package org.opensecretmanager.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import java.time.LocalDate
import java.time.ZoneOffset
import org.opensecretmanager.vault.CardFill

/** What a field of a card form asks for, as the fill screen says it. */
enum class CardPart(val said: String) {
    NUMBER("number"),
    CARDHOLDER("cardholder's name"),
    EXPIRY("expiry"),
    EXPIRY_MONTH("expiry month"),
    EXPIRY_YEAR("expiry year"),
    SECURITY_CODE("security code"),
}

/**
 * A field of a card form: what it asks for, how it takes a value (one of
 * [View.AUTOFILL_TYPE_TEXT], [View.AUTOFILL_TYPE_LIST], and
 * [View.AUTOFILL_TYPE_DATE]), a list's choices as it shows them, and the
 * most characters it takes (0 for no limit), by which a number split over
 * several fields is split and an expiry written.
 */
data class CardField(val id: AutofillId, val part: CardPart, val type: Int, val options: List<String>, val maxLength: Int)

/**
 * A card form on the screen that asks: the fields a card goes into, found
 * by what they say to autofill (an app's hints, a page's `autocomplete`)
 * or else by their names, the app that shows them, and the page it says it
 * shows, if any, as for a login ([Form]). Only fields drawn with a size
 * count, so that a field the owner cannot see takes nothing: a page or an
 * app could otherwise hide one, to have the security code with the number.
 * A screen with no field for the number is no card form. [focused]: one of
 * its fields has the focus, so that a screen with a login form too is
 * offered a card there.
 */
data class CardForm(
    val packageName: String,
    val webDomain: String?,
    val webScheme: String?,
    val fields: List<CardField>,
    val focused: Boolean = false,
) {
    /** What it asks for, in a card's order, for the fill screen to say. */
    val asks: List<CardPart>
        get() = CardPart.entries.filter { part -> fields.any { it.part == part } }

    /** The values of [card] for the fields that take them: none for what the card does not have. */
    fun values(card: CardFill): List<Pair<AutofillId, AutofillValue>> {
        val month = card.expiryMonth.toIntOrNull()?.takeIf { it in 1..12 }
        val year = card.expiryYear.toIntOrNull()?.let { if (it < 100) 2000 + it else it }
        val digits = card.number.filter { it in '0'..'9' }
        val numbers = numberParts(digits)
        return fields.mapNotNull { field ->
            val value = when (field.part) {
                CardPart.NUMBER -> numbers[field.id]?.let(AutofillValue::forText)
                CardPart.CARDHOLDER -> card.cardholder.takeIf { it.isNotEmpty() }?.let(AutofillValue::forText)
                CardPart.SECURITY_CODE -> card.securityCode.takeIf { it.isNotEmpty() }?.let(AutofillValue::forText)
                CardPart.EXPIRY -> if (month == null || year == null) null else expiry(field, month, year)
                CardPart.EXPIRY_MONTH -> month?.let { inField(field, it, "%02d".format(it)) }
                CardPart.EXPIRY_YEAR -> year?.let {
                    inField(field, it, if (field.maxLength == 2) "%02d".format(it % 100) else "$it", it % 100)
                }
            }
            value?.let { field.id to it }
        }
    }

    /**
     * The number as its fields take it: whole in one field, or in turn over
     * several, as many digits in each as it takes, or 4 where it says not.
     */
    private fun numberParts(digits: String): Map<AutofillId, String> {
        val numberFields = fields.filter { it.part == CardPart.NUMBER }
        if (digits.isEmpty()) return emptyMap()
        if (numberFields.size == 1) return mapOf(numberFields[0].id to digits)
        val parts = mutableMapOf<AutofillId, String>()
        var at = 0
        numberFields.forEachIndexed { index, field ->
            val length = if (index == numberFields.lastIndex) digits.length - at else field.maxLength.takeIf { it > 0 } ?: 4
            val part = digits.substring(at.coerceAtMost(digits.length), (at + length).coerceAtMost(digits.length))
            if (part.isNotEmpty()) parts[field.id] = part
            at += length
        }
        return parts
    }

    /** An expiry in one field: as many characters as it takes, MM/YY unless it says otherwise. */
    private fun expiry(field: CardField, month: Int, year: Int): AutofillValue? {
        val mm = "%02d".format(month)
        val yy = "%02d".format(year % 100)
        return when (field.type) {
            View.AUTOFILL_TYPE_DATE -> AutofillValue.forDate(LocalDate.of(year, month, 1).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli())
            View.AUTOFILL_TYPE_LIST -> field.options.indexOfFirst { option ->
                option.filter { it in '0'..'9' }.let { it == "$mm$yy" || it == "$mm$year" }
            }.takeIf { it >= 0 }?.let(AutofillValue::forList)
            else -> AutofillValue.forText(
                when (field.maxLength) {
                    4 -> "$mm$yy"
                    6 -> "$mm$year"
                    7 -> "$mm/$year"
                    else -> "$mm/$yy"
                },
            )
        }
    }

    /**
     * A month or a year in a field of its own: [text] in a text field, or
     * in a list the choice whose first number is [number] (or [short], a
     * year's last two digits), as "03", "3", "3월", or "2030" show them.
     */
    private fun inField(field: CardField, number: Int, text: String, short: Int? = null): AutofillValue? = when (field.type) {
        View.AUTOFILL_TYPE_LIST -> field.options.indexOfFirst { option ->
            FIRST_NUMBER.find(option)?.value?.toIntOrNull().let { it == number || (short != null && it == short) }
        }.takeIf { it >= 0 }?.let(AutofillValue::forList)
        View.AUTOFILL_TYPE_TEXT -> AutofillValue.forText(text)
        else -> null
    }

    fun toBundle() = Bundle().apply {
        putString(PACKAGE, packageName)
        putString(WEB_DOMAIN, webDomain)
        putString(WEB_SCHEME, webScheme)
        putParcelableArrayList(IDS, ArrayList(fields.map { it.id }))
        putIntArray(PARTS, fields.map { it.part.ordinal }.toIntArray())
        putIntArray(TYPES, fields.map { it.type }.toIntArray())
        putIntArray(MAX_LENGTHS, fields.map { it.maxLength }.toIntArray())
        fields.forEachIndexed { index, field -> putStringArray("$OPTIONS$index", field.options.toTypedArray()) }
    }

    companion object {
        private const val PACKAGE = "card.package"
        private const val WEB_DOMAIN = "card.webDomain"
        private const val WEB_SCHEME = "card.webScheme"
        private const val IDS = "card.ids"
        private const val PARTS = "card.parts"
        private const val TYPES = "card.types"
        private const val MAX_LENGTHS = "card.maxLengths"
        private const val OPTIONS = "card.options."

        private val FIRST_NUMBER = Regex("\\d+")

        @Suppress("DEPRECATION")
        fun fromBundle(extras: Bundle): CardForm? {
            val packageName = extras.getString(PACKAGE) ?: return null
            val ids = extras.getParcelableArrayList<AutofillId>(IDS) ?: return null
            val parts = extras.getIntArray(PARTS) ?: return null
            val types = extras.getIntArray(TYPES) ?: return null
            val maxLengths = extras.getIntArray(MAX_LENGTHS) ?: return null
            if (parts.size != ids.size || types.size != ids.size || maxLengths.size != ids.size) return null
            val fields = ids.mapIndexed { index, id ->
                CardField(
                    id,
                    CardPart.entries.getOrNull(parts[index]) ?: return null,
                    types[index],
                    extras.getStringArray("$OPTIONS$index").orEmpty().toList(),
                    maxLengths[index],
                )
            }
            return CardForm(packageName, extras.getString(WEB_DOMAIN), extras.getString(WEB_SCHEME), fields)
        }

        /** Finds a card form's fields, or null if the screen has no field for a card's number. */
        fun parse(structure: AssistStructure): CardForm? {
            val fields = mutableListOf<CardField>()
            var focused = false
            var webDomain: String? = null
            var webScheme: String? = null
            fun visit(node: AssistStructure.ViewNode) {
                if (webDomain == null && !node.webDomain.isNullOrBlank()) {
                    webDomain = node.webDomain
                    if (Build.VERSION.SDK_INT >= 28) webScheme = node.webScheme
                }
                // Nothing in a view that is not shown.
                if (node.visibility != View.VISIBLE || node.alpha == 0f) return
                val id = node.autofillId
                val part = partOf(node)
                if (id != null && part != null && node.width > 0 && node.height > 0 && node.autofillType in TYPES_TAKEN) {
                    fields += CardField(id, part, node.autofillType, node.autofillOptions.orEmpty().map { it.toString() }, maxLength(node))
                    if (node.isFocused) focused = true
                }
                for (index in 0 until node.childCount) visit(node.getChildAt(index))
            }
            for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode)
            if (fields.none { it.part == CardPart.NUMBER }) return null
            return CardForm(structure.activityComponent.packageName, webDomain, webScheme, fields, focused)
        }

        private val TYPES_TAKEN = setOf(View.AUTOFILL_TYPE_TEXT, View.AUTOFILL_TYPE_LIST, View.AUTOFILL_TYPE_DATE)

        private fun maxLength(node: AssistStructure.ViewNode): Int {
            val html = node.htmlInfo?.attributes.orEmpty()
                .firstOrNull { it.first.equals("maxlength", ignoreCase = true) }?.second?.toIntOrNull()
            return (html ?: node.maxTextLength).coerceAtLeast(0)
        }

        /** What a field of a card form asks for, by what it says to autofill, or else by its names. */
        private fun partOf(node: AssistStructure.ViewNode): CardPart? {
            val hints = Form.hints(node)
            when {
                hints.any { it == "creditcardnumber" || it == "cc-number" } -> return CardPart.NUMBER
                hints.any { it == "creditcardsecuritycode" || it == "cc-csc" } -> return CardPart.SECURITY_CODE
                hints.any { it == "creditcardexpirationdate" || it == "cc-exp" } -> return CardPart.EXPIRY
                hints.any { it == "creditcardexpirationmonth" || it == "cc-exp-month" } -> return CardPart.EXPIRY_MONTH
                hints.any { it == "creditcardexpirationyear" || it == "cc-exp-year" } -> return CardPart.EXPIRY_YEAR
                hints.any { it == "cc-name" } -> return CardPart.CARDHOLDER
            }
            // A field that says it is something else, as an email address, is not a card's.
            if (hints.any { it.isNotBlank() && it !in SAYS_NOTHING }) return null
            val names = Form.names(node)
            val words = names.flatMap(Form::words).toSet()
            val card = "card" in words || "cc" in words
            return when {
                Form.named(names, CODE_PARTS, CODE_WORDS) -> CardPart.SECURITY_CODE
                Form.named(names, NUMBER_PARTS, emptySet()) || (card && words.any { it in NUMBER_WORDS }) -> CardPart.NUMBER
                Form.named(names, EXPIRY_PARTS, EXPIRY_WORDS) -> when {
                    Form.named(names, MONTH_PARTS, MONTH_WORDS) -> CardPart.EXPIRY_MONTH
                    Form.named(names, YEAR_PARTS, YEAR_WORDS) -> CardPart.EXPIRY_YEAR
                    else -> CardPart.EXPIRY
                }
                Form.named(names, HOLDER_PARTS, emptySet()) || (card && "name" in words) -> CardPart.CARDHOLDER
                else -> null
            }
        }

        /** What pages say of a field that asks for nothing in particular. */
        private val SAYS_NOTHING = setOf("off", "on")
        // In a name, anywhere; Korean words take particles after them.
        private val CODE_PARTS = listOf("cvc", "cvv", "csc", "securitycode", "security_code", "security-code", "cardcode", "card_code", "보안코드", "보안 코드")
        private val CODE_WORDS = setOf("cid")
        private val NUMBER_PARTS = listOf("cardnumber", "card_number", "card-number", "cardno", "card_no", "ccnumber", "cc_number", "ccnum", "카드번호", "카드 번호")
        private val NUMBER_WORDS = setOf("number", "num", "no")
        private val EXPIRY_PARTS = listOf("expir", "유효기간", "만료")
        private val EXPIRY_WORDS = setOf("exp")
        private val MONTH_PARTS = listOf("month", "월")
        private val MONTH_WORDS = setOf("mm")
        private val YEAR_PARTS = listOf("year", "년")
        private val YEAR_WORDS = setOf("yy", "yyyy")
        private val HOLDER_PARTS = listOf("cardholder", "card_holder", "card-holder", "nameoncard", "name_on_card", "holdername", "holder_name", "카드소유자", "소유자", "명의")
    }
}
