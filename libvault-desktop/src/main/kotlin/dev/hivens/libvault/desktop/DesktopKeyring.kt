package dev.hivens.libvault.desktop

import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.internal.KeyringBackend
import dev.hivens.libvault.internal.ProbeResult
import dev.hivens.libvault.linux.SecretServiceVault
import dev.hivens.libvault.macos.KeychainVault
import dev.hivens.libvault.windows.CredentialManagerVault
import org.slf4j.LoggerFactory

/**
 * The desktop OS keyrings, picked by `os.name`. Core's `Vault` finds it through
 * the ServiceLoader registration in META-INF/services, which needs a class with
 * a no-argument constructor rather than an object.
 */
internal class DesktopKeyring : KeyringBackend {

    private val log = LoggerFactory.getLogger("dev.hivens.libvault.Vault")

    private enum class Os { Linux, Windows, MacOs, Other }

    private val os: Os = System.getProperty("os.name", "").lowercase().let {
        when {
            it.contains("linux") || it.contains("bsd") -> Os.Linux
            it.contains("win") -> Os.Windows
            it.contains("mac") || it.contains("darwin") -> Os.MacOs
            else -> Os.Other
        }
    }

    override val label: String = when (os) {
        Os.Linux -> "secret-service (D-Bus)"
        Os.Windows -> "credential-manager (DPAPI)"
        Os.MacOs -> "keychain (SecItem)"
        Os.Other -> "unsupported"
    }

    override fun open(config: VaultConfig): ProbeResult = when (os) {
        Os.Linux -> SecretServiceVault.create(config)
        Os.Windows -> CredentialManagerVault.create(config)
        Os.MacOs -> KeychainVault.create(config)
        Os.Other -> {
            log.info("no OS keyring backend for os.name={}", System.getProperty("os.name"))
            ProbeResult.Unavailable(VaultAvailability.Unsupported)
        }
    }

    override fun collections(config: VaultConfig): List<String> {
        if (os != Os.Linux) return emptyList()
        val opened = SecretServiceVault.create(config) as? ProbeResult.Opened ?: return emptyList()
        return try {
            (opened.vault as SecretServiceVault).collectionLabels()
        } finally {
            opened.vault.close()
        }
    }
}
