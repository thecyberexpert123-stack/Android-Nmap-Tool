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
private const val KEY_PRIMARY_BASE_URL = "base_url"
private const val KEY_PRIMARY_ENCRYPTED_TOKEN = "encrypted_token"
private const val KEY_LAN_AGENT_BASE_URL = "lan_agent_base_url"
private const val KEY_LAN_AGENT_ENCRYPTED_TOKEN = "lan_agent_encrypted_token"
private const val PRIMARY_KEYSTORE_ALIAS = "android_nmap_remote_token"
private const val LAN_AGENT_KEYSTORE_ALIAS = "android_nmap_lan_agent_token"
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val AES_MODE = "AES/GCM/NoPadding"

data class RemoteEndpointSettings(
    val baseUrl: String = "",
    val bearerToken: String = "",
)

data class DelegatedExecutorSettingsBundle(
    val primary: RemoteEndpointSettings = RemoteEndpointSettings(),
    val lanAgent: RemoteEndpointSettings = RemoteEndpointSettings(),
)

class RemoteSettingsStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun read(): RemoteEndpointSettings = readPrimary()

    fun readPrimary(): RemoteEndpointSettings =
        RemoteEndpointSettings(
            baseUrl = preferences.getString(KEY_PRIMARY_BASE_URL, "").orEmpty(),
            bearerToken = preferences.getString(KEY_PRIMARY_ENCRYPTED_TOKEN, null)?.let { decrypt(PRIMARY_KEYSTORE_ALIAS, it) }.orEmpty(),
        )

    fun readLanAgent(): RemoteEndpointSettings =
        RemoteEndpointSettings(
            baseUrl = preferences.getString(KEY_LAN_AGENT_BASE_URL, "").orEmpty(),
            bearerToken = preferences.getString(KEY_LAN_AGENT_ENCRYPTED_TOKEN, null)?.let { decrypt(LAN_AGENT_KEYSTORE_ALIAS, it) }.orEmpty(),
        )

    fun readBundle(): DelegatedExecutorSettingsBundle = DelegatedExecutorSettingsBundle(
        primary = readPrimary(),
        lanAgent = readLanAgent(),
    )

    fun save(settings: RemoteEndpointSettings) {
        savePrimary(settings)
    }

    fun savePrimary(settings: RemoteEndpointSettings) {
        saveEndpoint(
            baseUrlKey = KEY_PRIMARY_BASE_URL,
            encryptedTokenKey = KEY_PRIMARY_ENCRYPTED_TOKEN,
            keystoreAlias = PRIMARY_KEYSTORE_ALIAS,
            settings = settings,
        )
    }

    fun saveLanAgent(settings: RemoteEndpointSettings) {
        saveEndpoint(
            baseUrlKey = KEY_LAN_AGENT_BASE_URL,
            encryptedTokenKey = KEY_LAN_AGENT_ENCRYPTED_TOKEN,
            keystoreAlias = LAN_AGENT_KEYSTORE_ALIAS,
            settings = settings,
        )
    }

    fun saveBundle(settings: DelegatedExecutorSettingsBundle) {
        savePrimary(settings.primary)
        saveLanAgent(settings.lanAgent)
    }

    private fun saveEndpoint(
        baseUrlKey: String,
        encryptedTokenKey: String,
        keystoreAlias: String,
        settings: RemoteEndpointSettings,
    ) {
        val edit = preferences.edit().putString(baseUrlKey, settings.baseUrl.trim())
        val normalizedToken = settings.bearerToken.trim()
        if (normalizedToken.isBlank()) {
            edit.remove(encryptedTokenKey)
        } else {
            edit.putString(encryptedTokenKey, encrypt(keystoreAlias, normalizedToken))
        }
        edit.apply()
    }

    private fun getOrCreateSecretKey(keystoreAlias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(keystoreAlias, null) as? SecretKey
        if (existing != null) {
            return existing
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun encrypt(keystoreAlias: String, plainText: String): String {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey(keystoreAlias))
        val encrypted = cipher.doFinal(plainText.toByteArray(StandardCharsets.UTF_8))
        val encodedIv = Base64.encodeToString(cipher.iv, Base64.NO_WRAP)
        val encodedPayload = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        return "$encodedIv:$encodedPayload"
    }

    private fun decrypt(keystoreAlias: String, encoded: String): String =
        runCatching {
            val pieces = encoded.split(':', limit = 2)
            require(pieces.size == 2) { "Encrypted token payload is invalid." }
            val cipher = Cipher.getInstance(AES_MODE)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateSecretKey(keystoreAlias),
                javax.crypto.spec.GCMParameterSpec(128, Base64.decode(pieces[0], Base64.NO_WRAP)),
            )
            val clearBytes = cipher.doFinal(Base64.decode(pieces[1], Base64.NO_WRAP))
            String(clearBytes, StandardCharsets.UTF_8)
        }.getOrDefault("")
}
