package org.opensecretmanager.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The Android Keystore, which seals this device's network (TLS) key so that
 * the app's files alone do not give it away. Each sealing makes an AES-256
 * key of its own in the Keystore, under a random name, which never leaves
 * it; the network key is sealed under it with AES-GCM, inside the Keystore.
 * What is stored in the device's folder is the name, the nonce, and the
 * sealed key.
 *
 * The keys are usable without the owner's fingerprint or PIN and while the
 * phone is locked, so that a sync in the background can open the network
 * key, as it could when the key was kept in the file.
 */
object AndroidKeystore : PhoneKeystore {
    private const val STORE = "AndroidKeyStore"
    private const val PREFIX = "org.opensecretmanager.transport-key."
    /** The form of what [seal] returns. */
    private const val FORM: Byte = 1
    private const val NAME = 16
    private const val NONCE = 12
    private val BOUND = "osm transport key".toByteArray()

    private fun alias(name: ByteArray) = PREFIX + name.joinToString("") { "%02x".format(it) }

    /** What is bound to the sealed key besides the key: its form and its name. */
    private fun bound(name: ByteArray) = BOUND + byteArrayOf(FORM) + name

    override fun seal(key: ByteArray): ByteArray = unavailableOnFailure {
        val name = ByteArray(NAME).also { SecureRandom().nextBytes(it) }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias(name),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        val wrapping = generator.generateKey()
        // The Keystore chooses the nonce.
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapping)
        cipher.updateAAD(bound(name))
        val sealed = cipher.doFinal(key)
        val nonce = cipher.iv
        check(nonce.size == NONCE)
        byteArrayOf(FORM) + name + nonce + sealed
    }

    override fun open(sealed: ByteArray): ByteArray {
        // Not in this form, or cut short: nothing this keystore sealed.
        if (sealed.size < 1 + NAME + NONCE || sealed[0] != FORM) throw KeystoreFailure.Lost()
        val name = sealed.copyOfRange(1, 1 + NAME)
        val nonce = sealed.copyOfRange(1 + NAME, 1 + NAME + NONCE)
        val body = sealed.copyOfRange(1 + NAME + NONCE, sealed.size)
        val wrapping = unavailableOnFailure {
            KeyStore.getInstance(STORE).apply { load(null) }.getKey(alias(name), null) as SecretKey?
        } ?: throw KeystoreFailure.Lost()
        return try {
            unavailableOnFailure {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, wrapping, GCMParameterSpec(128, nonce))
                cipher.updateAAD(bound(name))
                cipher.doFinal(body)
            }
        } catch (_: WrongKey) {
            throw KeystoreFailure.Lost()
        }
    }

    /** Forgets every key this keystore made: for tests only. */
    fun forgetEverything() {
        val store = KeyStore.getInstance(STORE).apply { load(null) }
        for (alias in store.aliases().toList()) {
            if (alias.startsWith(PREFIX)) store.deleteEntry(alias)
        }
    }

    /** How many keys this keystore holds: for tests only. */
    fun count(): Int =
        KeyStore.getInstance(STORE).apply { load(null) }.aliases().toList().count { it.startsWith(PREFIX) }

    private class WrongKey : Exception()

    /**
     * Runs [call]; a failure of the Keystore is [KeystoreFailure.Unavailable],
     * except a sealed key that does not open, which is [WrongKey].
     */
    private inline fun <T> unavailableOnFailure(call: () -> T): T =
        try {
            call()
        } catch (failure: KeystoreFailure) {
            throw failure
        } catch (_: AEADBadTagException) {
            throw WrongKey()
        } catch (_: Exception) {
            throw KeystoreFailure.Unavailable()
        }
}
