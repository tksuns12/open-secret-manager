package org.opensecretmanager.loginfixture

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText

/**
 * A sign-in on two screens, as many services ask: the account here, then
 * the password on the next screen ([TwoStepPasswordActivity]), in the same
 * task. Going on closes this screen.
 */
class TwoStepUsernameActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.two_step_username)
        val username = findViewById<EditText>(R.id.username)
        findViewById<Button>(R.id.next).setOnClickListener {
            startActivity(Intent(this, TwoStepPasswordActivity::class.java).putExtra(USERNAME, username.text.toString()))
            finish()
        }
    }

    companion object {
        const val USERNAME = "username"
    }
}
