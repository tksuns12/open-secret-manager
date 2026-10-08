package org.opensecretmanager.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/**
 * What a fill request found on the screen that asks: the fields a login
 * goes into (a username and a password, or a one-time code, or all three),
 * the app that shows them, and the web page's domain and scheme if the app
 * said it shows a page. Whether to believe the domain is decided elsewhere
 * ([Requester]).
 */
data class Form(
    val packageName: String,
    val webDomain: String?,
    val webScheme: String?,
    val username: AutofillId?,
    val password: AutofillId?,
    val oneTimeCode: AutofillId?,
) {
    fun toBundle() = Bundle().apply {
        putString(PACKAGE, packageName)
        putString(WEB_DOMAIN, webDomain)
        putString(WEB_SCHEME, webScheme)
        putParcelable(USERNAME, username)
        putParcelable(PASSWORD, password)
        putParcelable(ONE_TIME_CODE, oneTimeCode)
    }

    companion object {
        private const val PACKAGE = "form.package"
        private const val WEB_DOMAIN = "form.webDomain"
        private const val WEB_SCHEME = "form.webScheme"
        private const val USERNAME = "form.username"
        private const val PASSWORD = "form.password"
        private const val ONE_TIME_CODE = "form.oneTimeCode"

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

        /**
         * The first screen of a sign-in on two screens: a field that says it
         * is a username or an email address, and neither a password field nor
         * a one-time code field. Null for any other screen.
         */
        fun usernameScreen(structure: AssistStructure): Form? {
            val fields = mutableListOf<AssistStructure.ViewNode>()
            var webDomain: String? = null
            var webScheme: String? = null
            fun visit(node: AssistStructure.ViewNode) {
                if (webDomain == null && node.webDomain != null) {
                    webDomain = node.webDomain
                    if (Build.VERSION.SDK_INT >= 28) webScheme = node.webScheme
                }
                if (node.autofillType == View.AUTOFILL_TYPE_TEXT && node.autofillId != null && node.visibility == View.VISIBLE) {
                    fields += node
                }
                for (index in 0 until node.childCount) visit(node.getChildAt(index))
            }
            for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode)
            if (fields.any { isPassword(it) || isOneTimeCode(it) }) return null
            val username = fields.firstOrNull(::isUsername) ?: return null
            return Form(
                packageName = structure.activityComponent.packageName,
                webDomain = webDomain,
                webScheme = webScheme,
                username = username.autofillId,
                password = null,
                oneTimeCode = null,
            )
        }

        /** Finds the login fields, or null if the screen has neither a password field nor a one-time code field. */
        fun parse(structure: AssistStructure): Form? {
            val fields = mutableListOf<AssistStructure.ViewNode>()
            var webDomain: String? = null
            var webScheme: String? = null
            fun visit(node: AssistStructure.ViewNode) {
                if (webDomain == null && node.webDomain != null) {
                    webDomain = node.webDomain
                    if (Build.VERSION.SDK_INT >= 28) webScheme = node.webScheme
                }
                if (node.autofillType == View.AUTOFILL_TYPE_TEXT && node.autofillId != null && node.visibility == View.VISIBLE) {
                    fields += node
                }
                for (index in 0 until node.childCount) visit(node.getChildAt(index))
            }
            for (index in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(index).rootViewNode)

            val code = fields.firstOrNull(::isOneTimeCode)
            val passwordIndex = fields.indexOfFirst { isPassword(it) && !isOneTimeCode(it) }
            if (passwordIndex < 0 && code == null) return null
            // The username is the field that says it is one, or else the
            // text field just before the password. A screen that asks only
            // for a code has none.
            val username = if (passwordIndex < 0) {
                null
            } else {
                fields.firstOrNull(::isUsername)
                    ?: fields.take(passwordIndex).lastOrNull { !isPassword(it) && !isOneTimeCode(it) }
            }
            return Form(
                packageName = structure.activityComponent.packageName,
                webDomain = webDomain,
                webScheme = webScheme,
                username = username?.autofillId,
                password = fields.getOrNull(passwordIndex)?.autofillId,
                oneTimeCode = code?.autofillId,
            )
        }

        private fun hints(node: AssistStructure.ViewNode): List<String> =
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

        fun isUsername(node: AssistStructure.ViewNode): Boolean {
            if (isPassword(node) || isOneTimeCode(node)) return false
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
            return (node.inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_TEXT &&
                (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)
        }
    }
}
