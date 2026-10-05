package org.opensecretmanager.loginfixture

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.widget.EditText
import android.widget.TextView

/** A screen of the app's own that asks for a one-time code. It shows what was filled, for the tests to read. */
class CodeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.code)
        val code = findViewById<EditText>(R.id.code)
        val filled = findViewById<TextView>(R.id.filled)
        code.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(text: Editable?) {
                filled.text = text
            }
        })
    }
}
