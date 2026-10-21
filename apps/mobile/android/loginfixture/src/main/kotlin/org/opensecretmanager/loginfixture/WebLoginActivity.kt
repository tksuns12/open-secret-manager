package org.opensecretmanager.loginfixture

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ComponentName
import android.content.pm.PackageManager
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.TextView

/**
 * A login page of `origin` (an extra, `https://mail.example.test` if none)
 * in a web view, or, with the extra `page` set to `code`, a page that asks
 * for a one-time code, or set to `split`, a page whose ID and password are
 * each in a form of their own, which a web view reports to autofill one at
 * a time, or set to `card`, a checkout page's card form (see [CARD_PAGE]). The page is served from here, so no network is needed;
 * the web view still navigates to the address and reports its domain.
 * Signing in posts the form and shows the page again. With the extra
 * `asBrowser` true, the stand-in opens a link to any site from then on, as
 * a browser does ([AS_BROWSER]); false puts it back.
 */
class WebLoginActivity : Activity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.hasExtra("asBrowser")) {
            packageManager.setComponentEnabledSetting(
                ComponentName(this, AS_BROWSER),
                if (intent.getBooleanExtra("asBrowser", false)) {
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                } else {
                    PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
                },
                PackageManager.DONT_KILL_APP,
            )
        }
        setContentView(R.layout.web_login)
        val origin = intent.getStringExtra("origin") ?: "https://mail.example.test"
        val html = when (intent.getStringExtra("page")) {
            "code" -> CODE_PAGE
            "split" -> SPLIT_PAGE
            "card" -> CARD_PAGE
            else -> PAGE
        }
        val filled = findViewById<TextView>(R.id.filled)
        val page = findViewById<WebView>(R.id.page)
        page.settings.javaScriptEnabled = true
        page.addJavascriptInterface(
            object {
                @JavascriptInterface
                fun report(username: String, password: String) = runOnUiThread { filled.text = "$username|$password" }

                @JavascriptInterface
                fun reportCode(code: String) = runOnUiThread { filled.text = code }

                @JavascriptInterface
                fun reportCard(card: String) = runOnUiThread { filled.text = card }
            },
            "fixture",
        )
        page.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse =
                if (request.url.path == "/login") {
                    WebResourceResponse("text/html", "utf-8", html.byteInputStream())
                } else {
                    WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), "".byteInputStream())
                }
        }
        page.loadUrl("$origin/login")
    }

    private companion object {
        /** An alias of this page with the links of any site, off in the manifest. */
        const val AS_BROWSER = "org.opensecretmanager.loginfixture.AsBrowser"

        val PAGE = """
            <!doctype html>
            <meta name="viewport" content="width=device-width">
            <style>input, button { display: block; width: 90%; font-size: 22px; margin: 16px 0; }</style>
            <form method="post" action="/login">
              <button id="sign-in" type="submit">Sign in</button>
              <input id="username" type="text" name="username" autocomplete="username" placeholder="Username">
              <input id="password" type="password" name="password" autocomplete="current-password" placeholder="Password">
            </form>
            <script>
              setInterval(() => fixture.report(username.value, password.value), 200);
            </script>
        """.trimIndent()

        val SPLIT_PAGE = """
            <!doctype html>
            <meta name="viewport" content="width=device-width">
            <style>input { display: block; width: 90%; font-size: 22px; margin: 16px 0; }</style>
            <form id="id-form"><input id="userId" type="text" name="userId" placeholder="아이디"></form>
            <form id="pw-form"><input id="userPw" type="password" name="userPw" placeholder="비밀번호"></form>
            <script>
              setInterval(() => fixture.report(userId.value, userPw.value), 200);
            </script>
        """.trimIndent()

        /**
         * A card form as checkouts make them: the cardholder, the number split
         * over four fields of four digits, the month and the year as lists,
         * and the code, each saying what it is (`autocomplete`), and a second
         * code field drawn with no size. It reports what each holds, in order,
         * the field with no size last: `holder|number|month|year|code|hidden`.
         */
        val CARD_PAGE = """
            <!doctype html>
            <meta name="viewport" content="width=device-width">
            <style>input, select { display: block; width: 90%; font-size: 22px; margin: 12px 0; } .part { display: inline-block; width: 20%; }
              #hidden { width: 0; height: 0; padding: 0; border: 0; margin: 0; }</style>
            <form id="pay">
              <input id="holder" autocomplete="cc-name" placeholder="Name on card">
              <div><input class="part" id="n1" autocomplete="cc-number" maxlength="4" inputmode="numeric"><input class="part" id="n2" autocomplete="cc-number" maxlength="4" inputmode="numeric"><input class="part" id="n3" autocomplete="cc-number" maxlength="4" inputmode="numeric"><input class="part" id="n4" autocomplete="cc-number" maxlength="4" inputmode="numeric"></div>
              <select id="month" autocomplete="cc-exp-month"><option value="">MM</option><option>01</option><option>02</option><option>03</option><option>04</option><option>05</option><option>06</option><option>07</option><option>08</option><option>09</option><option>10</option><option>11</option><option>12</option></select>
              <select id="year" autocomplete="cc-exp-year"><option value="">YYYY</option><option>2026</option><option>2027</option><option>2028</option><option>2029</option><option>2030</option><option>2031</option><option>2032</option></select>
              <input id="code" autocomplete="cc-csc" inputmode="numeric" placeholder="CVC">
              <input id="hidden" autocomplete="cc-csc">
            </form>
            <script>
              setInterval(() => fixture.reportCard([holder.value, n1.value + n2.value + n3.value + n4.value, month.value, year.value, code.value, hidden.value].join("|")), 200);
            </script>
        """.trimIndent()

        val CODE_PAGE = """
            <!doctype html>
            <meta name="viewport" content="width=device-width">
            <style>input { display: block; width: 90%; font-size: 22px; margin: 16px 0; }</style>
            <form method="post" action="/login">
              <input id="code" type="text" name="code" autocomplete="one-time-code" inputmode="numeric" placeholder="Code">
            </form>
            <script>
              setInterval(() => fixture.reportCode(code.value), 200);
            </script>
        """.trimIndent()
    }
}
