package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.UnlockPolicy
import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultStatus
import dev.hivens.libvault.VaultTier
import org.slf4j.LoggerFactory

/**
 * Picks the backend for a platform's `open`, reports tier status for its
 * `probe`, and lists collections. Walks [VaultConfig.preferredTiers] in order
 * and guarantees a working vault at the bottom of the chain (software file when
 * allowed, else [NoneVault]). Never throws.
 *
 * The OS keyring is whatever [KeyringBackend] the platform module passes in.
 */
@InternalLibvaultApi
public object VaultSelector {

    private val log = LoggerFactory.getLogger("dev.hivens.libvault.Vault")

    public fun select(config: VaultConfig, keyring: KeyringBackend): SecretVault {
        for (tier in config.preferredTiers) {
            val vault = when (tier) {
                VaultTier.OsKeyring -> (openKeyring(config, keyring) as? ProbeResult.Opened)?.vault
                VaultTier.SoftwareFile -> if (config.allowSoftwareFallback) openSoftware(config) else null
                VaultTier.Memory -> MemoryVault()
                VaultTier.None -> NoneVault
            }
            if (vault != null) return announce(vault)
        }
        val floor = (if (config.allowSoftwareFallback) openSoftware(config) else null) ?: NoneVault
        return announce(floor)
    }

    public fun probe(config: VaultConfig, keyring: KeyringBackend): List<VaultStatus> =
        config.preferredTiers.map { statusFor(it, config, keyring) }

    public fun collections(config: VaultConfig, keyring: KeyringBackend): List<String> =
        runCatching { keyring.collections(config) }.getOrElse {
            log.info("OS keyring collections unavailable: {}", it.message ?: it.javaClass.simpleName)
            emptyList()
        }

    private fun statusFor(tier: VaultTier, config: VaultConfig, keyring: KeyringBackend): VaultStatus = when (tier) {
        VaultTier.OsKeyring ->
            // Force Never: a probe must classify, not prompt.
            when (val r = openKeyring(config.copy(unlockPolicy = UnlockPolicy.Never), keyring)) {
                is ProbeResult.Opened -> {
                    val backend = r.vault.backend
                    r.vault.close()
                    VaultStatus(VaultTier.OsKeyring, backend, VaultAvailability.Available)
                }
                is ProbeResult.Unavailable -> VaultStatus(VaultTier.OsKeyring, keyring.label, r.availability)
            }
        VaultTier.SoftwareFile -> VaultStatus(VaultTier.SoftwareFile, EncryptedFileVault.SOFTWARE_BACKEND, VaultAvailability.Available)
        VaultTier.Memory -> VaultStatus(VaultTier.Memory, "memory (process-local)", VaultAvailability.Available)
        VaultTier.None -> VaultStatus(VaultTier.None, "none (disabled)", VaultAvailability.Available)
    }

    private fun openKeyring(config: VaultConfig, keyring: KeyringBackend): ProbeResult =
        runCatching { keyring.open(config) }.getOrElse {
            log.info("OS keyring unavailable: {}", it.message ?: it.javaClass.simpleName)
            ProbeResult.Unavailable(VaultAvailability.LibraryUnavailable)
        }

    /** Null when the file vault cannot even be set up, e.g. a namespace that is no valid path here. */
    private fun openSoftware(config: VaultConfig): SecretVault? = runCatching {
        val path = config.softwareFilePath ?: DataDir.resolve(config.namespace)
        EncryptedFileVault.openSoftware(path, config.keyDerivation, config.opTimeoutMs)
    }.getOrElse {
        log.warn("software file tier unavailable: {}", it.message ?: it.javaClass.simpleName)
        null
    }

    private fun announce(vault: SecretVault): SecretVault {
        log.info("vault opened: tier={} backend={} secure={}", vault.tier, vault.backend, vault.secure)
        return vault
    }
}
