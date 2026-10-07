package org.opensecretmanager.loginfixture

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView

/**
 * A login form of the app's own. It shows what was filled, for the tests to
 * read. Signing in takes the form away and leaves the app open, as most
 * apps go on to their next screen: the system offers to save once the
 * form's fields are gone. (Android 15 and later start the save screen only
 * while the form's app is in front or has just left it, so an app that
 * closed itself would make the save depend on how soon Save is tapped.)
 */
class NativeLoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.native_login)
        val username = findViewById<EditText>(R.id.username)
        val password = findViewById<EditText>(R.id.password)
        val filled = findViewById<TextView>(R.id.filled)
        val show = object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(text: Editable?) {
                filled.text = "${username.text}|${password.text}"
            }
        }
        username.addTextChangedListener(show)
        password.addTextChangedListener(show)
        val signIn = findViewById<Button>(R.id.sign_in)
        signIn.setOnClickListener { listOf(signIn, username, password).forEach { it.visibility = View.GONE } }
    }
}
