package org.opensecretmanager.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Unlocking with a fingerprint or the face instead of typing the password.
 *
 * The device's password is kept on the phone encrypted with a key that
 * Android's keystore holds in the phone's secure hardware and uses only
 * after a strong biometric check. A new fingerprint or face enrolled on the
 * phone makes the key unusable, and the password must be typed again to
 * turn this back on. The vault itself still opens with its password: this
 * only spares typing it.
 */
class BiometricUnlock(context: Context) {
    private val preferences =
        context.getSharedPreferences("biometric-unlock", Context.MODE_PRIVATE)
    private val manager = BiometricManager.from(context)

    /** The phone has a strong biometric enrolled. */
    val available: Boolean
        get() = manager.canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    val enabled: Boolean
        get() = preferences.contains(CIPHERTEXT)

    /** A cipher to encrypt the password with, once a biometric check lets it run. */
    fun cipherToStore(): Cipher {
        deleteKey()
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, newKey()) }
    }

    fun store(cipher: Cipher, password: String) {
        val ciphertext = cipher.doFinal(password.toByteArray(Charsets.UTF_8))
        preferences.edit()
            .putString(CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .putString(IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .apply()
    }

    /**
     * A cipher to decrypt the password with, once a biometric check lets it
     * run, or null if the key no longer works (a new biometric was
     * enrolled), which turns this off.
     */
    fun cipherToRead(): Cipher? {
        val iv = preferences.getString(IV, null) ?: return null
        val key = existingKey() ?: return null.also { disable() }
        return try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)))
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            disable()
            null
        }
    }

    fun read(cipher: Cipher): String {
        val ciphertext = Base64.decode(preferences.getString(CIPHERTEXT, "")!!, Base64.NO_WRAP)
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }

    fun disable() {
        preferences.edit().clear().apply()
        deleteKey()
    }

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(KEY_ALIAS, null) as SecretKey?

    private fun deleteKey() {
        keyStore().deleteEntry(KEY_ALIAS)
    }

    private fun newKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                // Every use needs its own biometric check.
                if (Build.VERSION.SDK_INT >= 30) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "device-password"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val CIPHERTEXT = "ciphertext"
        const val IV = "iv"
    }
}
