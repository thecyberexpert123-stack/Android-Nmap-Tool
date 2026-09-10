package com.thecyberexpert123.androidnmap.settings

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.thecyberexpert123.nmaptool.contract.RemoteCapabilitiesResponse
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private const val PREFERENCES_NAME = "remote_settings"
private const val KEY_PRIMARY_BASE_URL = "base_url"
private const val KEY_PRIMARY_ENCRYPTED_TOKEN = "encrypted_token"
private const val KEY_LAN_AGENT_BASE_URL = "lan_agent_base_url"
private const val KEY_LAN_AGENT_ENCRYPTED_TOKEN = "lan_agent_encrypted_token"
private const val KEY_PRIMARY_CAPABILITY_SNAPSHOT = "primary_capability_snapshot"
private const val KEY_PRIMARY_CAPABILITY_CHECKED_AT = "primary_capability_checked_at"
private const val KEY_LAN_AGENT_CAPABILITY_SNAPSHOT = "lan_agent_capability_snapshot"
private const val KEY_LAN_AGENT_CAPABILITY_CHECKED_AT = "lan_agent_capability_checked_at"
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

enum class DelegatedExecutorSlot {
    PRIMARY,
    LAN_AGENT,
}

@Serializable
data class CachedRemoteCapabilitiesSnapshot(
    val capabilities: RemoteCapabilitiesResponse,
    val checkedAtEpochMillis: Long,
)

data class DelegatedExecutorCapabilitySnapshotBundle(
    val primary: CachedRemoteCapabilitiesSnapshot? = null,
    val lanAgent: CachedRemoteCapabilitiesSnapshot? = null,
)

class RemoteSettingsStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = false
    }

    fun read(): RemoteEndpointSettings = readPrimary()

    fun readPrimary(): RemoteEndpointSettings =
        readEndpoint(
            baseUrlKey = KEY_PRIMARY_BASE_URL,
            encryptedTokenKey = KEY_PRIMARY_ENCRYPTED_TOKEN,
            keystoreAlias = PRIMARY_KEYSTORE_ALIAS,
        )

    fun readLanAgent(): RemoteEndpointSettings =
        readEndpoint(
            baseUrlKey = KEY_LAN_AGENT_BASE_URL,
            encryptedTokenKey = KEY_LAN_AGENT_ENCRYPTED_TOKEN,
            keystoreAlias = LAN_AGENT_KEYSTORE_ALIAS,
        )

    fun readBundle(): DelegatedExecutorSettingsBundle = DelegatedExecutorSettingsBundle(
        primary = readPrimary(),
        lanAgent = readLanAgent(),
    )

    fun readCapabilitySnapshotBundle(): DelegatedExecutorCapabilitySnapshotBundle = DelegatedExecutorCapabilitySnapshotBundle(
        primary = readCapabilitySnapshot(
            snapshotKey = KEY_PRIMARY_CAPABILITY_SNAPSHOT,
            checkedAtKey = KEY_PRIMARY_CAPABILITY_CHECKED_AT,
        ),
        lanAgent = readCapabilitySnapshot(
            snapshotKey = KEY_LAN_AGENT_CAPABILITY_SNAPSHOT,
            checkedAtKey = KEY_LAN_AGENT_CAPABILITY_CHECKED_AT,
        ),
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

    fun saveCapabilitySnapshot(
        slot: DelegatedExecutorSlot,
        snapshot: CachedRemoteCapabilitiesSnapshot,
    ) {
        val (snapshotKey, checkedAtKey) = capabilityKeys(slot)
        preferences.edit()
            .putString(snapshotKey, json.encodeToString(CachedRemoteCapabilitiesSnapshot.serializer(), snapshot))
            .putLong(checkedAtKey, snapshot.checkedAtEpochMillis)
            .apply()
    }

    fun clearCapabilitySnapshot(slot: DelegatedExecutorSlot) {
        val (snapshotKey, checkedAtKey) = capabilityKeys(slot)
        preferences.edit()
            .remove(snapshotKey)
            .remove(checkedAtKey)
            .apply()
    }

    private fun saveEndpoint(
        baseUrlKey: String,
        encryptedTokenKey: String,
        keystoreAlias: String,
        settings: RemoteEndpointSettings,
    ) {
        val previous = readEndpoint(baseUrlKey, encryptedTokenKey, keystoreAlias)
        val normalizedBaseUrl = settings.baseUrl.trim()
        val normalizedToken = settings.bearerToken.trim()
        val edit = preferences.edit().putString(baseUrlKey, normalizedBaseUrl)
        if (normalizedToken.isBlank()) {
            edit.remove(encryptedTokenKey)
        } else {
            edit.putString(encryptedTokenKey, encrypt(keystoreAlias, normalizedToken))
        }
        if (
            previous.baseUrl.trim() != normalizedBaseUrl ||
            previous.bearerToken.trim() != normalizedToken
        ) {
            val (snapshotKey, checkedAtKey) = capabilityKeysForBaseUrlKey(baseUrlKey)
            edit.remove(snapshotKey)
            edit.remove(checkedAtKey)
        }
        edit.apply()
    }

    private fun readEndpoint(
        baseUrlKey: String,
        encryptedTokenKey: String,
        keystoreAlias: String,
    ): RemoteEndpointSettings = RemoteEndpointSettings(
        baseUrl = preferences.getString(baseUrlKey, "").orEmpty(),
        bearerToken = preferences.getString(encryptedTokenKey, null)?.let { decrypt(keystoreAlias, it) }.orEmpty(),
    )

    private fun readCapabilitySnapshot(
        snapshotKey: String,
        checkedAtKey: String,
    ): CachedRemoteCapabilitiesSnapshot? {
        val encoded = preferences.getString(snapshotKey, null) ?: return null
        val checkedAt = preferences.getLong(checkedAtKey, 0L)
        return runCatching {
            val decoded = json.decodeFromString(CachedRemoteCapabilitiesSnapshot.serializer(), encoded)
            decoded.copy(checkedAtEpochMillis = checkedAt.takeIf { it > 0L } ?: decoded.checkedAtEpochMillis)
        }.getOrElse {
            preferences.edit().remove(snapshotKey).remove(checkedAtKey).apply()
            null
        }
    }

    private fun capabilityKeys(slot: DelegatedExecutorSlot): Pair<String, String> = when (slot) {
        DelegatedExecutorSlot.PRIMARY -> KEY_PRIMARY_CAPABILITY_SNAPSHOT to KEY_PRIMARY_CAPABILITY_CHECKED_AT
        DelegatedExecutorSlot.LAN_AGENT -> KEY_LAN_AGENT_CAPABILITY_SNAPSHOT to KEY_LAN_AGENT_CAPABILITY_CHECKED_AT
    }

    private fun capabilityKeysForBaseUrlKey(baseUrlKey: String): Pair<String, String> = when (baseUrlKey) {
        KEY_PRIMARY_BASE_URL -> KEY_PRIMARY_CAPABILITY_SNAPSHOT to KEY_PRIMARY_CAPABILITY_CHECKED_AT
        KEY_LAN_AGENT_BASE_URL -> KEY_LAN_AGENT_CAPABILITY_SNAPSHOT to KEY_LAN_AGENT_CAPABILITY_CHECKED_AT
        else -> error("Unsupported delegated executor key: $baseUrlKey")
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
