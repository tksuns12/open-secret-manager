package org.opensecretmanager.app

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/** The system's fingerprint prompts, for unlocking and for keeping the password for it. */
class FingerprintPrompts(
    private val activity: FragmentActivity,
    private val biometric: BiometricUnlock,
    private val session: VaultSession,
) {
    private fun prompt(title: String, negative: String, cipher: javax.crypto.Cipher, onCipher: (javax.crypto.Cipher) -> Unit) {
        BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    result.cryptoObject?.cipher?.let(onCipher)
                }
            },
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
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
        prompt("Unlock the vault", "Use the password", cipher) { session.unlock(biometric.read(it)) }
    }

    /** After an unlock with [password]: keeps it for the next unlock, once a fingerprint allows. */
    fun keep(password: String) {
        prompt("Unlock with a fingerprint next time", "Not now", biometric.cipherToStore()) { biometric.store(it, password) }
    }
}
