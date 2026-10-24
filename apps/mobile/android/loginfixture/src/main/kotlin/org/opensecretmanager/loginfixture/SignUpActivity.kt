package org.opensecretmanager.loginfixture

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.InputFilter
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView

/**
 * A sign-up form of the app's own: an email address and a new password
 * typed twice. With the extra `maxLength`, the password fields take at most
 * that many characters, and cut what is longer, as an app's do. It shows
 * what was filled, `email|password|again`, for the tests to read. Signing
 * up takes the form away, which is when the system would offer to save.
 */
class SignUpActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.sign_up)
        val email = findViewById<EditText>(R.id.email)
        val password = findViewById<EditText>(R.id.new_password)
        val again = findViewById<EditText>(R.id.confirm_password)
        val filled = findViewById<TextView>(R.id.filled)
        val most = intent.getIntExtra("maxLength", 0)
        if (most > 0) listOf(password, again).forEach { it.filters = arrayOf(InputFilter.LengthFilter(most)) }
        val show = object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(text: Editable?) {
                filled.text = "${email.text}|${password.text}|${again.text}"
            }
        }
        listOf(email, password, again).forEach { it.addTextChangedListener(show) }
        val signUp = findViewById<Button>(R.id.sign_up)
        signUp.setOnClickListener { listOf(signUp, email, password, again).forEach { it.visibility = View.GONE } }
    }
}
