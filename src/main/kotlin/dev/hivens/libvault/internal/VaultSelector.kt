package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.UnlockPolicy
import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultStatus
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.linux.SecretServiceVault
import dev.hivens.libvault.macos.KeychainVault
import dev.hivens.libvault.windows.CredentialManagerVault
import org.slf4j.LoggerFactory

/**
 * Picks the backend for [dev.hivens.libvault.Vault.open], reports tier status for
 * [dev.hivens.libvault.Vault.probe], and lists collections. Walks
 * [VaultConfig.preferredTiers] in order and guarantees a working vault at the
 * bottom of the chain (software file when allowed, else [NoneVault]). Never throws.
 */
internal object VaultSelector {

    private val log = LoggerFactory.getLogger("dev.hivens.libvault.Vault")

    fun select(config: VaultConfig): SecretVault {
        for (tier in config.preferredTiers) {
            val vault = when (tier) {
                VaultTier.OsKeyring -> (openKeyring(config) as? ProbeResult.Opened)?.vault
                VaultTier.SoftwareFile -> if (config.allowSoftwareFallback) openSoftware(config) else null
                VaultTier.Memory -> MemoryVault()
                VaultTier.None -> NoneVault
            }
            if (vault != null) return announce(vault)
        }
        val floor = if (config.allowSoftwareFallback) openSoftware(config) else NoneVault
        return announce(floor)
    }

    fun probe(config: VaultConfig): List<VaultStatus> = config.preferredTiers.map { statusFor(it, config) }

    fun collections(config: VaultConfig): List<String> {
        val opened = openKeyring(config) as? ProbeResult.Opened ?: return emptyList()
        return try {
            (opened.vault as? SecretServiceVault)?.collectionLabels() ?: emptyList()
        } finally {
            opened.vault.close()
        }
    }

    private fun statusFor(tier: VaultTier, config: VaultConfig): VaultStatus = when (tier) {
        VaultTier.OsKeyring ->
            // Force Never: a probe must classify, not prompt.
            when (val r = openKeyring(config.copy(unlockPolicy = UnlockPolicy.Never))) {
                is ProbeResult.Opened -> {
                    val backend = r.vault.backend
                    r.vault.close()
                    VaultStatus(VaultTier.OsKeyring, backend, VaultAvailability.Available)
                }
                is ProbeResult.Unavailable -> VaultStatus(VaultTier.OsKeyring, osKeyringLabel(), r.availability)
            }
        VaultTier.SoftwareFile -> VaultStatus(VaultTier.SoftwareFile, "aes-256-gcm file", VaultAvailability.Available)
        VaultTier.Memory -> VaultStatus(VaultTier.Memory, "memory (process-local)", VaultAvailability.Available)
        VaultTier.None -> VaultStatus(VaultTier.None, "none (disabled)", VaultAvailability.Available)
    }

    private fun openKeyring(config: VaultConfig): ProbeResult {
        val os = System.getProperty("os.name", "").lowercase()
        return runCatching {
            when {
                os.contains("linux") || os.contains("bsd") -> SecretServiceVault.create(config)
                os.contains("win") -> CredentialManagerVault.create(config)
                os.contains("mac") || os.contains("darwin") -> KeychainVault.create(config)
                else -> {
                    log.info("no OS keyring backend for os.name={}", os)
                    ProbeResult.Unavailable(VaultAvailability.Unsupported)
                }
            }
        }.getOrElse {
            log.info("OS keyring unavailable: {}", it.message ?: it.javaClass.simpleName)
            ProbeResult.Unavailable(VaultAvailability.LibraryUnavailable)
        }
    }

    private fun osKeyringLabel(): String {
        val os = System.getProperty("os.name", "").lowercase()
        return when {
            os.contains("linux") || os.contains("bsd") -> "secret-service (D-Bus)"
            os.contains("win") -> "credential-manager (DPAPI)"
            os.contains("mac") || os.contains("darwin") -> "keychain (SecItem)"
            else -> "unsupported"
        }
    }

    private fun openSoftware(config: VaultConfig): SecretVault {
        val path = config.softwareFilePath ?: DataDir.resolve(config.namespace)
        return SoftwareFileVault.open(path, config.keyDerivation)
    }

    private fun announce(vault: SecretVault): SecretVault {
        log.info("vault opened: tier={} backend={} secure={}", vault.tier, vault.backend, vault.secure)
        return vault
    }
}
