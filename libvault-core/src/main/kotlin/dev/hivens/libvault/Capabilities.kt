package dev.hivens.libvault

/**
 * Capability discovery. Optional vault features live on sibling interfaces rather
 * than on [SecretVault] itself, so a backend advertises only what it can actually
 * do (the memory tier isn't unlockable; [None][VaultTier.None] enumerates nothing
 * meaningful). Ask a vault for a capability; null means it doesn't have it.
 *
 * ```
 * vault.asUnlockable()?.takeIf { it.isLocked() }?.unlock()
 * val keys = vault.asEnumerable()?.list().orEmpty()
 * ```
 */

public fun SecretVault.asEnumerable(): EnumerableVault? = this as? EnumerableVault

public fun SecretVault.asDescribable(): DescribableVault? = this as? DescribableVault

public fun SecretVault.asLabeled(): LabeledVault? = this as? LabeledVault

public fun SecretVault.asUnlockable(): UnlockableVault? = this as? UnlockableVault

public fun SecretVault.asMigratable(): MigratableVault? = this as? MigratableVault

public fun SecretVault.asWatchable(): WatchableVault? = this as? WatchableVault
