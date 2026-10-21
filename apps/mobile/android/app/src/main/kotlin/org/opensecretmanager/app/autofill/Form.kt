package org.opensecretmanager.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * What a fill request found on the screen that asks: the fields a login
 * goes into (a username and a password, or a one-time code, or all three,
 * or a username alone),
 * the app that shows them, and the web page's domain and scheme if the app
 * said it shows a page: those of the first view that names a domain, past
 * any that names an empty one, as the outermost view of a page in Firefox
 * can. Whether to believe the domain is decided elsewhere ([Requester]).
 * [page]: the fields are a page's, in a web view or a browser, which may
 * have told of one form of the page only, where a screen of an app tells of
 * all its fields.
 */
data class Form(
    val packageName: String,
    val webDomain: String?,
    val webScheme: String?,
    val username: AutofillId?,
    val password: AutofillId?,
    val oneTimeCode: AutofillId?,
    val page: Boolean = false,
) {
    /** Asks for a one-time code, and neither a username nor a password. */
    val codeOnly: Boolean
        get() = username == null && password == null

    fun toBundle() = Bundle().apply {
        putString(PACKAGE, packageName)
        putString(WEB_DOMAIN, webDomain)
        putString(WEB_SCHEME, webScheme)
        putParcelable(USERNAME, username)
        putParcelable(PASSWORD, password)
        putParcelable(ONE_TIME_CODE, oneTimeCode)
        putBoolean(PAGE, page)
    }

    companion object {
        private const val PACKAGE = "form.package"
        private const val WEB_DOMAIN = "form.webDomain"
        private const val WEB_SCHEME = "form.webScheme"
        private const val USERNAME = "form.username"
        private const val PASSWORD = "form.password"
        private const val ONE_TIME_CODE = "form.oneTimeCode"
        private const val PAGE = "form.page"

        @Suppress("DEPRECATION")
        fun fromBundle(extras: Bundle): Form? {
            val packageName = extras.getString(PACKAGE) ?: return null
            return Form(
                packageName,
                extras.getString(WEB_DOMAIN),
                extras.getString(WEB_SCHEME),
                extras.getParcelable(USERNAME),
                extras.getParcelable(PASSWORD),
                extras.getParcelable(ONE_TIME_CODE),
                extras.getBoolean(PAGE),
            )
        }

        /** What the fields [ids] held when the screen was read: their text, by field. */
        fun values(structure: AssistStructure, ids: Set<AutofillId>): Map<AutofillId, String> {
            val found = mutableMapOf<AutofillId, String>()
            fun visit(node: AssistStructure.ViewNode) {
                val id = node.autofillId
                val value = node.autofillValue
                if (id != null && id in ids && value != null && value.isText) found[id] = value.textValue.toString()
                for (index in 0 until node.childCount) visit(node.getChildAt(index))
            }
            for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode)
            return found
        }

        /** A text field on the screen, and the window it is in. */
        private class Field(val node: AssistStructure.ViewNode, val window: Int)

        /** The text fields shown, in the order of the screen's tree, and the page's domain and scheme. */
        private class Fields(val all: List<Field>, val webDomain: String?, val webScheme: String?)

        private fun fields(structure: AssistStructure): Fields {
            val fields = mutableListOf<Field>()
            var webDomain: String? = null
            var webScheme: String? = null
            fun visit(node: AssistStructure.ViewNode, window: Int) {
                if (webDomain == null && !node.webDomain.isNullOrBlank()) {
                    webDomain = node.webDomain
                    if (Build.VERSION.SDK_INT >= 28) webScheme = node.webScheme
                }
                if (node.autofillType == View.AUTOFILL_TYPE_TEXT && node.autofillId != null && node.visibility == View.VISIBLE) {
                    fields += Field(node, window)
                }
                for (index in 0 until node.childCount) visit(node.getChildAt(index), window)
            }
            for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode, index)
            return Fields(fields, webDomain, webScheme)
        }

        /**
         * The first screen of a sign-in on two screens: a field that says it
         * is a username or an email address, or is named one, and neither a
         * password field nor a one-time code field. Null for any other screen.
         */
        fun usernameScreen(structure: AssistStructure): Form? {
            val fields = fields(structure)
            if (fields.all.any { isPasswordField(it.node) || isOneTimeCode(it.node) }) return null
            val username = fields.all.firstOrNull { isUsername(it.node) } ?: return null
            return Form(
                packageName = structure.activityComponent.packageName,
                webDomain = fields.webDomain,
                webScheme = fields.webScheme,
                username = username.node.autofillId,
                password = null,
                oneTimeCode = null,
                page = username.node.htmlInfo != null,
            )
        }

        /** Finds the login fields, or null if the screen has neither a password field nor a one-time code field. */
        fun parse(structure: AssistStructure): Form? {
            val fields = fields(structure)
            val code = fields.all.firstOrNull { isOneTimeCode(it.node) }
            // Many apps type their ID field as a password shown as typed, to
            // keep the keyboard from suggesting words: a password field that
            // hides what is typed is the password, if there is one.
            val passwords = fields.all.filter { isPasswordField(it.node) }
            val password = passwords.firstOrNull { !typedAsShownPassword(it.node) } ?: passwords.firstOrNull()
            if (password == null && code == null) return null
            // A screen that asks only for a code has no username.
            val username = password?.let { usernameFor(fields.all, it) }
            return Form(
                packageName = structure.activityComponent.packageName,
                webDomain = fields.webDomain,
                webScheme = fields.webScheme,
                username = username?.node?.autofillId,
                password = password?.node?.autofillId,
                oneTimeCode = code?.node?.autofillId,
                page = listOfNotNull(username, password, code).any { it.node.htmlInfo != null },
            )
        }

        /**
         * The username that goes with [password], in its window: the field
         * nearest before it that says or is named a username, or else the
         * text field just before it, or else a field after it that says or is
         * named one. A field named a search, or the like, is none.
         */
        private fun usernameFor(fields: List<Field>, password: Field): Field? {
            val window = fields.filter { it.window == password.window }
            val at = window.indexOf(password)
            fun candidate(field: Field) = field !== password && !isOneTimeCode(field.node) && !namedOtherThanUsername(field.node) &&
                (!isPassword(field.node) || typedAsShownPassword(field.node))
            val before = window.take(at).filter(::candidate)
            return before.lastOrNull { isUsername(it.node) }
                ?: before.lastOrNull()
                ?: window.drop(at + 1).firstOrNull { candidate(it) && isUsername(it.node) }
        }

        /** What a field says it is to autofill: an app's hints and a page's `autocomplete`, in lower case. */
        internal fun hints(node: AssistStructure.ViewNode): List<String> =
            node.autofillHints.orEmpty().map { it.lowercase() } +
                node.htmlInfo?.attributes.orEmpty()
                    .filter { it.first.equals("autocomplete", ignoreCase = true) }
                    .flatMap { it.second.lowercase().split(' ') }

        private fun htmlType(node: AssistStructure.ViewNode): String? =
            node.htmlInfo?.attributes.orEmpty()
                .firstOrNull { it.first.equals("type", ignoreCase = true) }?.second?.lowercase()

        fun isPassword(node: AssistStructure.ViewNode): Boolean {
            val hints = hints(node)
            if (hints.any { it == View.AUTOFILL_HINT_PASSWORD.lowercase() || it == "current-password" || it == "new-password" }) return true
            if (htmlType(node) == "password") return true
            val type = node.inputType
            val variation = type and InputType.TYPE_MASK_VARIATION
            return when (type and InputType.TYPE_MASK_CLASS) {
                InputType.TYPE_CLASS_TEXT -> variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                    variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                InputType.TYPE_CLASS_NUMBER -> variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
                else -> false
            }
        }

        /**
         * A field for a code from an authenticator app, as the vault has:
         * one that says so in an app's autofill hints or a page's
         * `autocomplete`. A field for a code sent by text message or email
         * is not one.
         */
        fun isOneTimeCode(node: AssistStructure.ViewNode): Boolean =
            hints(node).any { it == "2faappotpcode" || it == "one-time-code" }

        /**
         * Typed as a password shown as typed, with nothing else saying it is
         * one: what a password's "show" makes it, and what many apps make an
         * ID field.
         */
        private fun typedAsShownPassword(node: AssistStructure.ViewNode): Boolean {
            val hints = hints(node)
            if (hints.any { it == View.AUTOFILL_HINT_PASSWORD.lowercase() || it == "current-password" || it == "new-password" }) return false
            if (htmlType(node) == "password") return false
            return (node.inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT &&
                (node.inputType and InputType.TYPE_MASK_VARIATION) == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        }

        /** A password field, but for one typed as a password shown as typed that is named a username. */
        private fun isPasswordField(node: AssistStructure.ViewNode): Boolean =
            isPassword(node) && !isOneTimeCode(node) && !(typedAsShownPassword(node) && namedUsername(node))

        fun isUsername(node: AssistStructure.ViewNode): Boolean {
            if (isOneTimeCode(node) || (isPassword(node) && !typedAsShownPassword(node))) return false
            if (namedOtherThanUsername(node)) return false
            val hints = hints(node)
            if (hints.any {
                    it == View.AUTOFILL_HINT_USERNAME.lowercase() || it == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase() ||
                        it == "email" || it == "username"
                }
            ) {
                return true
            }
            if (htmlType(node) == "email") return true
            val variation = node.inputType and InputType.TYPE_MASK_VARIATION
            if ((node.inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT &&
                (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)
            ) {
                return true
            }
            return namedUsername(node)
        }

        /**
         * What a field is named: an app's resource name for it and its
         * placeholder, or a page's name, id, label, and placeholder for it.
         * Apps that say nothing of a field to autofill often name it.
         */
        internal fun names(node: AssistStructure.ViewNode): List<String> =
            listOfNotNull(node.idEntry, node.hint) +
                node.htmlInfo?.attributes.orEmpty()
                    .filter { it.first.lowercase() in NAME_ATTRIBUTES }
                    .mapNotNull { it.second }

        /** The words of a name, `loginID` and `login_id` alike giving `login` and `id`. */
        internal fun words(name: String): List<String> =
            name.split(WORD_BREAK).map { it.lowercase() }.filter { it.isNotEmpty() }

        internal fun named(names: List<String>, parts: List<String>, wholeWords: Set<String>): Boolean =
            names.any { name -> parts.any { it in name.lowercase() } || words(name).any { it in wholeWords } }

        /** Named a username, an email address, a phone number, or an ID, and not a password. */
        private fun namedUsername(node: AssistStructure.ViewNode): Boolean = namesUsername(names(node))

        private fun namedOtherThanUsername(node: AssistStructure.ViewNode): Boolean = namesOtherThanUsername(names(node))

        /** Whether a field so named is a username, as [namedUsername] tells, from its names alone. */
        fun namesUsername(names: List<String>): Boolean =
            named(names, USERNAME_PARTS, USERNAME_WORDS) && !named(names, PASSWORD_PARTS, PASSWORD_WORDS)

        /** Whether a field so named is a search, a captcha, or the like. */
        fun namesOtherThanUsername(names: List<String>): Boolean = named(names, NOT_USERNAME_PARTS, emptySet())

        private val NAME_ATTRIBUTES = setOf("name", "id", "label", "aria-label", "placeholder")
        private val WORD_BREAK = Regex("[^\\p{L}\\p{N}]+|(?<=\\p{Ll})(?=\\p{Lu})|(?<=\\p{Lu})(?=\\p{Lu}\\p{Ll})|(?<=\\p{L})(?=\\p{N})|(?<=\\p{N})(?=\\p{L})")
        // In a name, anywhere; Korean words take particles after them.
        private val USERNAME_PARTS = listOf("username", "userid", "email", "phone", "login", "아이디", "이메일", "사번", "휴대폰", "전화", "사용자")
        // As a word of a name only: `id` is in many words.
        private val USERNAME_WORDS = setOf("id", "uid", "user", "mail", "mobile", "tel")
        private val PASSWORD_PARTS = listOf("password", "passwd", "pswd", "비밀번호", "패스워드")
        private val PASSWORD_WORDS = setOf("pw", "pwd", "pass")
        private val NOT_USERNAME_PARTS = listOf("search", "find", "recipient", "captcha", "검색")
    }
}
