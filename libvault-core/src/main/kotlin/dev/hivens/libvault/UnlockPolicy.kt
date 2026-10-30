package dev.hivens.libvault

/**
 * Whether [Vault.open] may interactively unlock a locked OS keyring during open.
 * The default keeps the never-hang contract; the opt-in is for a host app that
 * has decided (e.g. after a [Vault.probe] showed [VaultAvailability.Locked] and
 * the user clicked "unlock") to surface a prompt.
 */
public enum class UnlockPolicy {
    /** Never prompt. A locked keyring degrades to the next tier. The default. */
    Never,

    /**
     * If the keyring is locked, surface the system unlock prompt and wait up to
     * [VaultConfig.unlockTimeoutMs]. On a confirmed unlock the keyring tier opens;
     * on denial/timeout it degrades like [Never].
     */
    IfLocked,
}
