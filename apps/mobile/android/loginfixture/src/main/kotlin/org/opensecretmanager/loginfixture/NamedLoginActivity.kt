package org.opensecretmanager.loginfixture

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView

/**
 * A login form whose fields say nothing to autofill, as many apps' do: they
 * are only named. With the extra `form` set to `shown`, the ID field is
 * typed as a password shown as typed; otherwise a field for a company code
 * sits between the ID and the password. It shows what each field holds, in
 * order, for the tests to read.
 */
class NamedLoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(if (intent.getStringExtra("form") == "shown") R.layout.named_login_shown else R.layout.named_login_between)
        val form = findViewById<ViewGroup>(R.id.form)
        val fields = (0 until form.childCount).map(form::getChildAt).filterIsInstance<EditText>()
        val filled = findViewById<TextView>(R.id.filled)
        val show = object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(text: Editable?) {
                filled.text = fields.joinToString("|") { it.text }
            }
        }
        fields.forEach { it.addTextChangedListener(show) }
    }
}
