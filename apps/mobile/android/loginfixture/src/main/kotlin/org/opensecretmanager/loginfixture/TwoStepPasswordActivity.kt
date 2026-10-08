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
 * The second screen of [TwoStepUsernameActivity]'s sign-in: the password
 * only. It shows the account it was given and what was typed or filled, for
 * the tests to read; signing in takes the form away and leaves the app open.
 */
class TwoStepPasswordActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.two_step_password)
        val account = intent.getStringExtra(TwoStepUsernameActivity.USERNAME).orEmpty()
        val password = findViewById<EditText>(R.id.password)
        val filled = findViewById<TextView>(R.id.filled)
        filled.text = "$account|"
        password.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(text: Editable?) {
                filled.text = "$account|${password.text}"
            }
        })
        val signIn = findViewById<Button>(R.id.sign_in)
        signIn.setOnClickListener { listOf(signIn, password).forEach { it.visibility = View.GONE } }
    }
}
