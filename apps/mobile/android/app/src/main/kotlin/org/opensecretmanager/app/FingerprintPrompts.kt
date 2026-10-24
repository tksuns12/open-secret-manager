package org.opensecretmanager.app

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * The system's fingerprint prompts, for unlocking and for keeping the
 * password for it. [asker]: who an unlock is for, on a fill, save, or
 * passkey screen, said under the prompt, which covers the screen's own line.
 */
class FingerprintPrompts(
    private val activity: FragmentActivity,
    private val biometric: BiometricUnlock,
    private val session: VaultSession,
    private val asker: String? = null,
) {
    /** A prompt is shown: another would cancel it. */
    private var prompting = false

    private fun prompt(title: String, subtitle: String?, negative: String, cipher: javax.crypto.Cipher, onCipher: (javax.crypto.Cipher) -> Unit) {
        if (prompting) return
        prompting = true
        BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    prompting = false
                    result.cryptoObject?.cipher?.let(onCipher)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    prompting = false
                    when (errorCode) {
                        // The owner chose the password, or turned away: the
                        // screen's own button stays.
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED -> Unit
                        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT ->
                            session.notify("Too many tries with a fingerprint · use the password")
                        else -> session.notify(errString.toString())
                    }
                }
            },
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply { subtitle?.let(::setSubtitle) }
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setNegativeButtonText(negative)
                .build(),
            BiometricPrompt.CryptoObject(cipher),
        )
    }

    fun unlock() {
        val cipher = biometric.cipherToRead() ?: run {
            session.notify("Unlock with the password once: the fingerprints on this phone changed")
            return
        }
        prompt("Unlock the vault", asker, "Use the password", cipher) { session.unlock(biometric.read(it)) }
    }

    /** After an unlock with [password]: keeps it for the next unlock, once a fingerprint allows. */
    fun keep(password: String) {
        prompt("Unlock with a fingerprint next time", null, "Not now", biometric.cipherToStore()) { biometric.store(it, password) }
    }
}
