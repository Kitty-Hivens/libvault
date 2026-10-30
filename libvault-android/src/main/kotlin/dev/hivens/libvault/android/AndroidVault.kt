package dev.hivens.libvault.android

import android.content.Context
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultStatus
import dev.hivens.libvault.internal.KeyringBackend
import dev.hivens.libvault.internal.ProbeResult
import dev.hivens.libvault.internal.VaultSelector
import java.io.File

/**
 * Entry point on Android, the counterpart of the desktop `Vault`. Open the best
 * available store for a [VaultConfig] and use the returned [SecretVault]:
 *
 * ```
 * AndroidVault.open(context, VaultConfig(namespace = "com.example.app")).use { vault ->
 *     vault.store("accessToken", token)
 *     val back = vault.retrieve("accessToken")
 * }
 * ```
 *
 * The OS keyring tier here is the Android Keystore: secrets are encrypted under
 * a non-exportable AES-256-GCM key it holds, and only the ciphertext reaches the
 * app's storage. The tiers, the fallback and the failure model are the same as
 * on the desktop. [open] degrades through [VaultConfig.preferredTiers], never
 * throws on a backend fault and never hangs.
 *
 * Files live under [Context.getNoBackupFilesDir], so they stay out of cloud
 * backups: a Keystore key never leaves the device, and a restored file would
 * arrive without it. A null [VaultConfig.softwareFilePath] puts the software
 * tier there too.
 */
public object AndroidVault {

    /**
     * Select and open a backend. Blocks the caller at most
     * [VaultConfig.probeTimeoutMs] while setting up the Keystore. Call it off
     * the main thread: the first open generates the key, and a Keystore can
     * take a while to answer.
     */
    public fun open(context: Context, config: VaultConfig): SecretVault {
        val dir = context.applicationContext.noBackupFilesDir
        return VaultSelector.select(withDefaultPath(dir, config), Keyring(dir))
    }

    /**
     * Classify each [VaultConfig.preferredTiers] entry without opening a live
     * vault. On Android the keyring tier is [VaultAvailability.Available] or
     * [VaultAvailability.ServiceUnavailable], never locked.
     */
    public fun probe(context: Context, config: VaultConfig): List<VaultStatus> {
        val dir = context.applicationContext.noBackupFilesDir
        return VaultSelector.probe(withDefaultPath(dir, config), Keyring(dir))
    }

    private fun withDefaultPath(noBackupDir: File, config: VaultConfig): VaultConfig =
        if (config.softwareFilePath != null) {
            config
        } else {
            config.copy(softwareFilePath = File(KeystoreVault.namespaceDir(noBackupDir, config.namespace), "vault.bin").toPath())
        }

    private class Keyring(private val noBackupDir: File) : KeyringBackend {
        override val label: String = KeystoreVault.BACKEND
        override fun open(config: VaultConfig): ProbeResult = KeystoreVault.create(noBackupDir, config)
    }
}
