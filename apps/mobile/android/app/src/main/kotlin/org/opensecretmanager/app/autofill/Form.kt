package org.opensecretmanager.app.autofill

import android.app.assist.AssistStructure
import android.graphics.RectF
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import org.opensecretmanager.vault.Asks

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
 * [newPasswords]: the fields of a sign-up or a change of password that take
 * a new password, and its confirmation, which a password made for it fills
 * (see [parse]); [newPasswordMaxLength] the most characters they all take,
 * or 0 if none says.
 */
data class Form(
    val packageName: String,
    val webDomain: String?,
    val webScheme: String?,
    val username: AutofillId?,
    val password: AutofillId?,
    val oneTimeCode: AutofillId?,
    val page: Boolean = false,
    val newPasswords: List<AutofillId> = emptyList(),
    val newPasswordMaxLength: Int = 0,
) {
    /** Asks for a one-time code, and neither a username nor a password. */
    val codeOnly: Boolean
        get() = username == null && password == null

    /** What the vault fills it with: a login, a code, or both. */
    val asks: Asks
        get() = when {
            codeOnly -> Asks.ONE_TIME_CODE
            oneTimeCode != null -> Asks.LOGIN_AND_ONE_TIME_CODE
            else -> Asks.LOGIN
        }

    fun toBundle() = Bundle().apply {
        putString(PACKAGE, packageName)
        putString(WEB_DOMAIN, webDomain)
        putString(WEB_SCHEME, webScheme)
        putParcelable(USERNAME, username)
        putParcelable(PASSWORD, password)
        putParcelable(ONE_TIME_CODE, oneTimeCode)
        putBoolean(PAGE, page)
        putParcelableArrayList(NEW_PASSWORDS, ArrayList(newPasswords))
        putInt(NEW_PASSWORD_MAX_LENGTH, newPasswordMaxLength)
    }

    /** A normalized web origin inherited from a view node or its ancestors. */
    internal data class WebOrigin(val domain: String, val scheme: String?)

    /** Result of resolving a node's web origin against its inherited ancestor origin. */
    internal sealed interface OriginStep {
        data class Same(val origin: WebOrigin?) : OriginStep
        data object Conflict : OriginStep
    }

    companion object {
        private const val PACKAGE = "form.package"
        private const val WEB_DOMAIN = "form.webDomain"
        private const val WEB_SCHEME = "form.webScheme"
        private const val USERNAME = "form.username"
        private const val PASSWORD = "form.password"
        private const val ONE_TIME_CODE = "form.oneTimeCode"
        private const val PAGE = "form.page"
        private const val NEW_PASSWORDS = "form.newPasswords"
        private const val NEW_PASSWORD_MAX_LENGTH = "form.newPasswordMaxLength"

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
                extras.getParcelableArrayList<AutofillId>(NEW_PASSWORDS).orEmpty(),
                extras.getInt(NEW_PASSWORD_MAX_LENGTH),
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

        internal const val MIN_VISIBLE_ALPHA = 0.1f
        internal const val MIN_FIELD_SIZE = 4f

        internal fun nodeWebOrigin(node: AssistStructure.ViewNode): WebOrigin? {
            val domain = node.webDomain?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
            val scheme = if (Build.VERSION.SDK_INT >= 28) {
                node.webScheme?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
            } else {
                null
            }
            return WebOrigin(domain, scheme)
        }

        /**
         * Resolves [node]'s effective web origin against [inherited].
         *
         * A child subtree that introduces a different domain or a different
         * scheme (such as a cross-origin or HTTP iframe nested inside an HTTPS
         * page) returns [OriginStep.Conflict] so the entire subtree is pruned
         * and can never receive credentials meant for the outer origin.
         */
        internal fun resolveOrigin(inherited: WebOrigin?, node: AssistStructure.ViewNode): OriginStep {
            val own = nodeWebOrigin(node) ?: return OriginStep.Same(inherited)
            if (inherited == null) return OriginStep.Same(own)
            if (own.domain != inherited.domain) return OriginStep.Conflict
            if (Build.VERSION.SDK_INT >= 28 && inherited.scheme != null && own.scheme != null && own.scheme != inherited.scheme) {
                return OriginStep.Conflict
            }
            return OriginStep.Same(WebOrigin(inherited.domain, inherited.scheme ?: own.scheme))
        }

        /**
         * Whether an inline HTML `style` attribute hides an element via
         * `display: none`, `visibility: hidden`/`collapse`, or low `opacity`.
         */
        internal fun isHiddenInlineStyle(style: String): Boolean {
            for (declaration in style.split(';')) {
                val colon = declaration.indexOf(':')
                if (colon <= 0) continue
                val property = declaration.substring(0, colon).trim().lowercase()
                val rawValue = declaration.substring(colon + 1)
                    .substringBefore('!')
                    .trim()
                    .lowercase()
                when (property) {
                    "display" -> if (rawValue == "none") return true
                    "visibility" -> if (rawValue == "hidden" || rawValue == "collapse") return true
                    "opacity" -> {
                        val alpha = if (rawValue.endsWith('%')) {
                            rawValue.dropLast(1).trim().toFloatOrNull()?.div(100f)
                        } else {
                            rawValue.toFloatOrNull()
                        }
                        if (alpha != null && alpha < MIN_VISIBLE_ALPHA) return true
                    }
                }
            }
            return false
        }

        /**
         * Whether [node] (and therefore its entire subtree) is hidden from the
         * owner: invisible/gone, near-transparent, marked `hidden` /
         * `aria-hidden="true"` in HTML, or hidden via inline CSS `style`.
         */
        internal fun isHiddenNode(node: AssistStructure.ViewNode): Boolean {
            if (node.visibility != View.VISIBLE || node.alpha < MIN_VISIBLE_ALPHA) return true
            val attrs = node.htmlInfo?.attributes.orEmpty()
            return attrs.any { attr ->
                attr.first.equals("hidden", ignoreCase = true) ||
                    (attr.first.equals("aria-hidden", ignoreCase = true) && attr.second.equals("true", ignoreCase = true)) ||
                    (attr.first.equals("style", ignoreCase = true) && isHiddenInlineStyle(attr.second.orEmpty()))
            }
        }

        /** Bounds of [node] in window coordinates, applying any matrix transform. */
        internal fun nodeBounds(node: AssistStructure.ViewNode, parentLeft: Float, parentTop: Float): RectF {
            val matrix = node.transformation
            return if (matrix == null) {
                val left = parentLeft + node.left
                val top = parentTop + node.top
                RectF(left, top, left + node.width, top + node.height)
            } else {
                val rect = RectF(0f, 0f, node.width.toFloat(), node.height.toFloat())
                matrix.mapRect(rect)
                rect.offset(parentLeft + node.left, parentTop + node.top)
                rect
            }
        }

        /**
         * Whether [bounds] are large enough and positioned on-screen (horizontally
         * and not pushed above the top edge) so the owner can see the field.
         */
        internal fun isVisibleBounds(bounds: RectF, windowWidth: Int): Boolean {
            if (bounds.width() < MIN_FIELD_SIZE || bounds.height() < MIN_FIELD_SIZE) return false
            if (bounds.right <= 0f || bounds.bottom <= 0f) return false
            if (windowWidth > 0 && bounds.left >= windowWidth.toFloat()) return false
            return true
        }

        /** A visible text field on the screen, scoped to its window and inherited web origin. */
        private class Field(val node: AssistStructure.ViewNode, val window: Int, val origin: WebOrigin?) {
            fun sameScope(other: Field): Boolean = window == other.window && origin == other.origin
        }

        /**
         * The visible, on-screen text fields in the order of the screen's tree,
         * pruning hidden subtrees and cross-origin nested frames. A page's
         * input that takes no text is none, though a browser may say it is a
         * text field: Firefox reports a box to tick so, and may report it
         * between a page's password and its ID.
         */
        private fun fields(structure: AssistStructure): List<Field> {
            val fields = mutableListOf<Field>()
            fun visit(
                node: AssistStructure.ViewNode,
                window: Int,
                windowWidth: Int,
                inherited: WebOrigin?,
                parentLeft: Float,
                parentTop: Float,
            ) {
                if (isHiddenNode(node)) return
                val origin = when (val step = resolveOrigin(inherited, node)) {
                    is OriginStep.Same -> step.origin
                    OriginStep.Conflict -> return
                }
                val bounds = nodeBounds(node, parentLeft, parentTop)
                if (node.autofillType == View.AUTOFILL_TYPE_TEXT &&
                    node.autofillId != null &&
                    isVisibleBounds(bounds, windowWidth) &&
                    htmlType(node) !in NOT_TEXT_TYPES
                ) {
                    fields += Field(node, window, origin)
                }
                val childLeft = bounds.left - node.scrollX
                val childTop = bounds.top - node.scrollY
                for (index in 0 until node.childCount) {
                    visit(node.getChildAt(index), window, windowWidth, origin, childLeft, childTop)
                }
            }
            for (index in 0 until structure.windowNodeCount) {
                val windowNode = structure.getWindowNodeAt(index)
                visit(windowNode.rootViewNode, index, windowNode.width, null, 0f, 0f)
            }
            return fields
        }

        /**
         * The first screen of a sign-in on two screens: a field that says it
         * is a username or an email address, or is named one, and neither a
         * password field nor a one-time code field. Null for any other screen.
         */
        fun usernameScreen(structure: AssistStructure): Form? {
            val all = fields(structure)
            if (all.any { isPasswordField(it.node) || isOneTimeCode(it.node) }) return null
            val focused = all.firstOrNull { it.node.isFocused }
            val candidates = focused?.let { f -> all.filter { it.sameScope(f) } } ?: all
            val username = candidates.firstOrNull { isUsername(it.node) && saysUsername(it.node) }
                ?: candidates.firstOrNull { isUsername(it.node) }
                ?: return null
            return Form(
                packageName = structure.activityComponent.packageName,
                webDomain = username.origin?.domain,
                webScheme = username.origin?.scheme,
                username = username.node.autofillId,
                password = null,
                oneTimeCode = null,
                page = username.node.htmlInfo != null,
            )
        }

        /** Finds the login fields, or null if the screen has neither a password field nor a one-time code field. */
        fun parse(structure: AssistStructure): Form? {
            val all = fields(structure)
            val focused = all.firstOrNull { it.node.isFocused }
            val focusedScope = focused?.let { f -> all.filter { it.sameScope(f) } }
            val pool = if (focusedScope != null && focusedScope.any { isPasswordField(it.node) || isOneTimeCode(it.node) }) {
                focusedScope
            } else {
                all
            }
            // Many apps type their ID field as a password shown as typed, to
            // keep the keyboard from suggesting words: a password field that
            // hides what is typed is the password, if there is one.
            val passwords = pool.filter { isPasswordField(it.node) }
            val password = passwords.firstOrNull { !typedAsShownPassword(it.node) } ?: passwords.firstOrNull()
            val code = if (password != null) {
                pool.firstOrNull { it.sameScope(password) && isOneTimeCode(it.node) }
            } else {
                pool.firstOrNull { isOneTimeCode(it.node) }
            }
            val anchor = password ?: code ?: return null
            val scoped = pool.filter { it.sameScope(anchor) }
            val scopedPasswords = passwords.filter { it.sameScope(anchor) }
            // A screen that asks only for a code has no username.
            val username = password?.let { usernameFor(scoped, it) }
            val new = password?.let { newPasswords(scopedPasswords, it) }.orEmpty()
            return Form(
                packageName = structure.activityComponent.packageName,
                webDomain = anchor.origin?.domain,
                webScheme = anchor.origin?.scheme,
                username = username?.node?.autofillId,
                password = password?.node?.autofillId,
                oneTimeCode = code?.node?.autofillId,
                page = listOfNotNull(username, password, code).any { it.node.htmlInfo != null },
                newPasswords = new.mapNotNull { it.node.autofillId },
                newPasswordMaxLength = new.map { maxLength(it.node) }.filter { it > 0 }.minOrNull() ?: 0,
            )
        }

        /**
         * The fields of [passwords] that take a new password, in the window
         * of [password]: those that say so (a page's `new-password`, an
         * app's `newPassword`), or else, of two or more that hide what is
         * typed, all but one that says or is named the current password, or
         * the first of three. A sign-in's one password field takes none, nor
         * a field shown as typed, as an ID typed so or a password "shown" is;
         * nor a field drawn with no size, which the owner cannot see, nor a
         * number's, as a PIN's.
         */
        private fun newPasswords(passwords: List<Field>, password: Field): List<Field> {
            val window = passwords.filter {
                it.window == password.window && it.node.width > 0 && it.node.height > 0 && !typedAsShownPassword(it.node) &&
                    (it.node.inputType and InputType.TYPE_MASK_CLASS) != InputType.TYPE_CLASS_NUMBER &&
                    htmlAttribute(it.node, "inputmode") != "numeric"
            }
            val said = window.filter { field -> hints(field.node).any { it == "new-password" || it == "newpassword" } }
            if (said.isNotEmpty()) return said
            if (window.size < 2) return emptyList()
            val current = window.filter { field ->
                hints(field.node).any { it == "current-password" } || named(names(field.node), CURRENT_PARTS, CURRENT_WORDS)
            }
            return when {
                current.isNotEmpty() -> window - current.toSet()
                window.size >= 3 -> window.drop(1)
                else -> window
            }
        }

        /** The most characters a field takes, by a page's `maxlength` or an app's filter; 0 if it does not say. */
        internal fun maxLength(node: AssistStructure.ViewNode): Int {
            val html = htmlAttribute(node, "maxlength")?.toIntOrNull()
            return (html ?: node.maxTextLength).coerceAtLeast(0)
        }

        private fun htmlAttribute(node: AssistStructure.ViewNode, name: String): String? =
            node.htmlInfo?.attributes.orEmpty().firstOrNull { it.first.equals(name, ignoreCase = true) }?.second?.lowercase()

        /**
         * The username that goes with [password], in its window: the field
         * nearest before it that says it is a username, or else the first
         * after it that says so, or else the field nearest before it named
         * one, or else the text field just before it, or else a field after
         * it named one. A field named a search, or the like, is none. Firefox
         * says which field is a page's username, but may report it after the
         * password, whatever the page's order.
         */
        private fun usernameFor(fields: List<Field>, password: Field): Field? {
            val window = fields.filter { it.window == password.window }
            val at = window.indexOf(password)
            fun candidate(field: Field) = field !== password && !isOneTimeCode(field.node) && !namedOtherThanUsername(field.node) &&
                (!isPassword(field.node) || typedAsShownPassword(field.node))
            val before = window.take(at).filter(::candidate)
            val after = window.drop(at + 1).filter { candidate(it) && isUsername(it.node) }
            return before.lastOrNull { isUsername(it.node) && saysUsername(it.node) }
                ?: after.firstOrNull { saysUsername(it.node) }
                ?: before.lastOrNull { isUsername(it.node) }
                ?: before.lastOrNull()
                ?: after.firstOrNull()
        }

        /** What a field says it is to autofill: an app's hints and a page's `autocomplete`, in lower case. */
        internal fun hints(node: AssistStructure.ViewNode): List<String> =
            node.autofillHints.orEmpty().map { it.lowercase() } +
                node.htmlInfo?.attributes.orEmpty()
                    .filter { it.first.equals("autocomplete", ignoreCase = true) }
                    .flatMap { it.second.trim().lowercase().split(WHITESPACE) }
                    .filter { it.isNotEmpty() }

        private fun htmlType(node: AssistStructure.ViewNode): String? =
            node.htmlInfo?.attributes.orEmpty()
                .firstOrNull { it.first.equals("type", ignoreCase = true) }?.second?.lowercase()

        fun isPassword(node: AssistStructure.ViewNode): Boolean {
            val hints = hints(node)
            if (hints.any { it == View.AUTOFILL_HINT_PASSWORD.lowercase() || it in PASSWORD_HINTS }) return true
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
            if (hints.any { it == View.AUTOFILL_HINT_PASSWORD.lowercase() || it in PASSWORD_HINTS }) return false
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
            if (saysUsername(node)) return true
            if (htmlType(node) == "email") return true
            val variation = node.inputType and InputType.TYPE_MASK_VARIATION
            if ((node.inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT &&
                (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)
            ) {
                return true
            }
            return namedUsername(node)
        }

        /** Says it is a username or an email address, in an app's hints or a page's `autocomplete`. */
        private fun saysUsername(node: AssistStructure.ViewNode): Boolean = hints(node).any {
            it == View.AUTOFILL_HINT_USERNAME.lowercase() || it == View.AUTOFILL_HINT_EMAIL_ADDRESS.lowercase() ||
                it == "email" || it == "username"
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
        private val WHITESPACE = Regex("\\s+")
        /** A page's `type`s of input that take no text. */
        private val NOT_TEXT_TYPES = setOf("checkbox", "radio", "submit", "button", "reset", "image", "file", "hidden", "range", "color")
        private val WORD_BREAK = Regex("[^\\p{L}\\p{N}]+|(?<=\\p{Ll})(?=\\p{Lu})|(?<=\\p{Lu})(?=\\p{Lu}\\p{Ll})|(?<=\\p{L})(?=\\p{N})|(?<=\\p{N})(?=\\p{L})")
        // In a name, anywhere; Korean words take particles after them.
        private val USERNAME_PARTS = listOf("username", "userid", "email", "phone", "login", "아이디", "이메일", "사번", "휴대폰", "전화", "사용자")
        // As a word of a name only: `id` is in many words.
        private val USERNAME_WORDS = setOf("id", "uid", "user", "mail", "mobile", "tel")
        private val PASSWORD_PARTS = listOf("password", "passwd", "pswd", "비밀번호", "패스워드")
        private val PASSWORD_WORDS = setOf("pw", "pwd", "pass")
        private val NOT_USERNAME_PARTS = listOf("search", "find", "recipient", "captcha", "검색")
        /** A page's for its passwords, and androidx's `newPassword` for an app's new one, in lower case. */
        private val PASSWORD_HINTS = setOf("current-password", "new-password", "newpassword")
        // Of a change of password, the field for the password it has now.
        private val CURRENT_PARTS = listOf("현재", "기존")
        private val CURRENT_WORDS = setOf("current", "old", "cur")
    }
}
