package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.linux.SecretServiceVault
import dev.hivens.libvault.macos.KeychainVault
import dev.hivens.libvault.windows.CredentialManagerVault
import org.slf4j.LoggerFactory

/**
 * Picks the backend for [dev.hivens.libvault.Vault.open]. Walks
 * [VaultConfig.preferredTiers] in order, returns the first tier that opens, and
 * guarantees a working vault at the bottom of the chain (software file when
 * allowed, else [NoneVault]). Never throws -- a backend that errors or times out
 * is simply skipped.
 */
internal object VaultSelector {

    private val log = LoggerFactory.getLogger("dev.hivens.libvault.Vault")

    fun select(config: VaultConfig): SecretVault {
        for (tier in config.preferredTiers) {
            val candidate = open(tier, config)
            if (candidate != null) return announce(candidate)
        }
        // Preferred list exhausted (or empty): fall to the guaranteed floor.
        val floor = if (config.allowSoftwareFallback) openSoftware(config) else NoneVault
        return announce(floor)
    }

    private fun open(tier: VaultTier, config: VaultConfig): SecretVault? = when (tier) {
        VaultTier.OsKeyring -> openKeyring(config)
        VaultTier.SoftwareFile -> if (config.allowSoftwareFallback) openSoftware(config) else null
        VaultTier.Memory -> MemoryVault()
        VaultTier.None -> NoneVault
    }

    /**
     * Try the platform's OS keyring. Each backend bounds its own native setup by
     * [VaultConfig.probeTimeoutMs] and returns null when the store is missing,
     * locked behind an un-answerable prompt, or wedged. The whole dispatch is
     * wrapped so an `UnsatisfiedLinkError` from native loading degrades too.
     */
    private fun openKeyring(config: VaultConfig): SecretVault? {
        val os = System.getProperty("os.name", "").lowercase()
        return runCatching {
            when {
                os.contains("linux") || os.contains("bsd") -> SecretServiceVault.create(config)
                os.contains("win") -> CredentialManagerVault.create(config)
                os.contains("mac") || os.contains("darwin") -> KeychainVault.create(config)
                else -> {
                    log.info("no OS keyring backend for os.name={}", os)
                    null
                }
            }
        }.onFailure {
            log.info("OS keyring unavailable: {}", it.message ?: it.javaClass.simpleName)
        }.getOrNull()
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
