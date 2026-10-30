package dev.hivens.libvault

/**
 * Why a tier is or isn't usable -- the detail behind the binary "opened / didn't".
 * Surfaced by [Vault.probe] and (for the OS keyring) by [UnlockableVault.isLocked]
 * so a host application can decide whether offering an unlock would even help.
 */
public enum class VaultAvailability {
    /** The backend opened and is serving operations. */
    Available,

    /**
     * An OS keyring is present and reachable, but its collection is locked behind
     * an interactive prompt. [Vault.open] degrades past it (never prompts); an
     * [UnlockableVault] can try to open it on explicit request.
     */
    Locked,

    /**
     * The keyring service is not answering -- no `org.freedesktop.secrets` owner
     * on the bus, `securityd` unreachable, etc. Offering unlock would not help.
     */
    ServiceUnavailable,

    /** The native library/symbols could not be loaded (no libdbus, no Advapi32). */
    LibraryUnavailable,

    /** This platform has no OS-keyring backend at all. */
    Unsupported,
}
