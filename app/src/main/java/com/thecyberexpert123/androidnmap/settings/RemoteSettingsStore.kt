package com.thecyberexpert123.androidnmap.settings

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val PREFERENCES_NAME = "remote_settings"
private const val KEY_BASE_URL = "base_url"
private const val KEY_ENCRYPTED_TOKEN = "encrypted_token"
private const val KEYSTORE_ALIAS = "android_nmap_remote_token"
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val AES_MODE = "AES/GCM/NoPadding"

data class RemoteEndpointSettings(
    val baseUrl: String = "",
    val bearerToken: String = "",
)

class RemoteSettingsStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun read(): RemoteEndpointSettings =
        RemoteEndpointSettings(
            baseUrl = preferences.getString(KEY_BASE_URL, "").orEmpty(),
            bearerToken = preferences.getString(KEY_ENCRYPTED_TOKEN, null)?.let(::decrypt).orEmpty(),
        )

    fun save(settings: RemoteEndpointSettings) {
        val edit = preferences.edit().putString(KEY_BASE_URL, settings.baseUrl.trim())
        val normalizedToken = settings.bearerToken.trim()
        if (normalizedToken.isBlank()) {
            edit.remove(KEY_ENCRYPTED_TOKEN)
        } else {
            edit.putString(KEY_ENCRYPTED_TOKEN, encrypt(normalizedToken))
        }
        edit.apply()
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey
        if (existing != null) {
            return existing
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun encrypt(plainText: String): String {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        val encrypted = cipher.doFinal(plainText.toByteArray(StandardCharsets.UTF_8))
        val encodedIv = Base64.encodeToString(cipher.iv, Base64.NO_WRAP)
        val encodedPayload = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        return "$encodedIv:$encodedPayload"
    }

    private fun decrypt(encoded: String): String =
        runCatching {
            val pieces = encoded.split(':', limit = 2)
            require(pieces.size == 2) { "Encrypted token payload is invalid." }
            val cipher = Cipher.getInstance(AES_MODE)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateSecretKey(),
                javax.crypto.spec.GCMParameterSpec(128, Base64.decode(pieces[0], Base64.NO_WRAP)),
            )
            val clearBytes = cipher.doFinal(Base64.decode(pieces[1], Base64.NO_WRAP))
            String(clearBytes, StandardCharsets.UTF_8)
        }.getOrDefault("")
}
