package org.opensecretmanager.loginfixture

import android.annotation.SuppressLint
import android.app.Activity
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
 * a time. The page is served from here, so no network is needed;
 * the web view still navigates to the address and reports its domain.
 * Signing in posts the form and shows the page again.
 */
class WebLoginActivity : Activity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.web_login)
        val origin = intent.getStringExtra("origin") ?: "https://mail.example.test"
        val html = when (intent.getStringExtra("page")) {
            "code" -> CODE_PAGE
            "split" -> SPLIT_PAGE
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
