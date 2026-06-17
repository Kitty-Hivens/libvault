package dev.hivens.libvault

/**
 * A [SecretVault] whose underlying store can be locked and interactively
 * unlocked. Only OS-keyring backends implement it. In practice only Linux Secret
 * Service does real work -- Windows Credential Manager and macOS Keychain unlock
 * with the login session, so they report unlocked and treat [unlock]/[lock] as
 * no-ops. Discover with [asUnlockable].
 *
 * [unlock] is the ONE operation allowed to block for tens of seconds (a human is
 * answering a system prompt). It is strictly opt-in: [Vault.open] never calls it.
 * It is bounded by [VaultConfig.unlockTimeoutMs], not `opTimeoutMs`.
 */
public interface UnlockableVault {
    /** True when the backing store is currently locked. Bounded read. */
    public fun isLocked(): Boolean

    /**
     * Attempt an interactive unlock, surfacing a system prompt the user answers.
     * Returns true on confirmed unlock, false on denial / cancel / timeout.
     * Blocks up to [VaultConfig.unlockTimeoutMs].
     */
    public fun unlock(): Boolean

    /** Relock the store where supported (Secret Service); no-op true elsewhere. */
    public fun lock(): Boolean
}
