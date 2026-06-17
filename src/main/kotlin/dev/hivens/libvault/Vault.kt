package dev.hivens.libvault

import dev.hivens.libvault.internal.VaultSelector

/**
 * Entry point. Open the best available secret store for a [VaultConfig] and use
 * the returned [SecretVault]:
 *
 * ```
 * Vault.open(VaultConfig(namespace = "dev.hivens.nexira")).use { vault ->
 *     vault.store("accessToken", token)
 *     val back = vault.retrieve("accessToken")
 * }
 * ```
 *
 * The returned vault is always usable -- [open] degrades through the tiers
 * (OS keyring -> encrypted file -> memory/none) and never throws on a backend
 * fault. Inspect [SecretVault.tier] / [SecretVault.secure] to learn how securely
 * the secret actually landed.
 */
public object Vault {

    /**
     * Select and open a backend. Blocks the caller at most
     * [VaultConfig.probeTimeoutMs] while probing the OS keyring; a locked or
     * wedged keyring is skipped rather than waited on. Never throws -- the only
     * exceptions reachable here are the `IllegalArgumentException`s a malformed
     * [VaultConfig] already raised at construction.
     */
    public fun open(config: VaultConfig): SecretVault = VaultSelector.select(config)

    /**
     * Classify each [VaultConfig.preferredTiers] entry without opening a live
     * vault. Lets a caller tell a locked keyring ([VaultAvailability.Locked] --
     * offer an unlock) from an absent one ([VaultAvailability.ServiceUnavailable]
     * -- don't). Non-interactive: never prompts, even if the config opts into
     * [UnlockPolicy.IfLocked]. Bounded by [VaultConfig.probeTimeoutMs] per tier.
     */
    public fun probe(config: VaultConfig): List<VaultStatus> = VaultSelector.probe(config)

    /**
     * Labels of the OS keyring's collections (Linux Secret Service). Empty on
     * platforms without separate collections (Windows/macOS) or when no keyring
     * is reachable.
     */
    public fun collections(config: VaultConfig): List<String> = VaultSelector.collections(config)
}
