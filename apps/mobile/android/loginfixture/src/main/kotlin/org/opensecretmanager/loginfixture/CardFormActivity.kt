package org.opensecretmanager.loginfixture

import android.app.Activity
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView

/**
 * A card form of an app's own (see `card_form`). It shows what each field
 * holds, in order, the field with no size last, for the tests to read:
 * `number|holder|month|year|code|hidden`.
 */
class CardFormActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.card_form)
        val month = findViewById<Spinner>(R.id.month)
        month.adapter = ArrayAdapter.createFromResource(this, R.array.months, android.R.layout.simple_spinner_item)
        val texts = listOf(R.id.number, R.id.holder, R.id.year, R.id.code, R.id.hidden_code).map { findViewById<EditText>(it) }
        val filled = findViewById<TextView>(R.id.filled)
        fun show() {
            val (number, holder, year, code, hidden) = texts.map { it.text.toString() }
            val chosen = month.selectedItem?.toString()?.takeIf { month.selectedItemPosition > 0 }.orEmpty()
            filled.text = listOf(number, holder, chosen, year, code, hidden).joinToString("|")
        }
        val watcher = object : TextWatcher {
            override fun beforeTextChanged(text: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(text: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(text: Editable?) = show()
        }
        texts.forEach { it.addTextChangedListener(watcher) }
        month.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) = show()
            override fun onNothingSelected(parent: AdapterView<*>?) = show()
        }
    }
}
