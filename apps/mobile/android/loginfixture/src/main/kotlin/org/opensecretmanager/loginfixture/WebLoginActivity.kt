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
 * in a web view. The page is served from here, so no network is needed;
 * the web view still navigates to the address and reports its domain.
 */
class WebLoginActivity : Activity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.web_login)
        val origin = intent.getStringExtra("origin") ?: "https://mail.example.test"
        val filled = findViewById<TextView>(R.id.filled)
        val page = findViewById<WebView>(R.id.page)
        page.settings.javaScriptEnabled = true
        page.addJavascriptInterface(
            object {
                @JavascriptInterface
                fun report(username: String, password: String) = runOnUiThread { filled.text = "$username|$password" }
            },
            "fixture",
        )
        page.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse =
                if (request.url.path == "/login") {
                    WebResourceResponse("text/html", "utf-8", PAGE.byteInputStream())
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
            <style>input { display: block; width: 90%; font-size: 22px; margin: 16px 0; }</style>
            <form>
              <input id="email" type="email" name="email" autocomplete="username" placeholder="Email">
              <input id="password" type="password" name="password" autocomplete="current-password" placeholder="Password">
            </form>
            <script>
              setInterval(() => fixture.report(email.value, password.value), 200);
            </script>
        """.trimIndent()
    }
}
