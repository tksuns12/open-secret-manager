package org.opensecretmanager.loginfixture

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.AttributeSet
import android.view.View
import android.view.ViewStructure
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * A login form that says it shows a page of `https://shop.example.test` in
 * its fields, inside a view that says it shows a page with no domain, as
 * the outermost view of a page in Firefox can. Otherwise as
 * [NativeLoginActivity]: signing in takes the form away.
 */
class NestedDomainLoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.nested_domain_login)
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

/** A view around a page's fields that names an empty domain. */
class EmptyDomainLayout(context: Context, attributes: AttributeSet?) : LinearLayout(context, attributes) {
    override fun onProvideAutofillStructure(structure: ViewStructure, flags: Int) {
        super.onProvideAutofillStructure(structure, flags)
        structure.setWebDomain("")
    }
}

/** A field of a page of `https://shop.example.test`. */
class ShopField(context: Context, attributes: AttributeSet?) : EditText(context, attributes) {
    override fun onProvideAutofillStructure(structure: ViewStructure, flags: Int) {
        super.onProvideAutofillStructure(structure, flags)
        structure.setWebDomain("https://shop.example.test")
    }
}
