package dev.hivens.libvault

/**
 * How securely a [SecretVault] actually stores its secrets, from strongest to
 * weakest. A caller inspects [SecretVault.tier] / [SecretVault.secure] to decide
 * whether a secret is safe to persist or should be re-requested each run.
 *
 * The ordering here is also the conventional preference order ([VaultConfig.preferredTiers]):
 * an OS keyring beats an obfuscated file beats volatile memory beats nothing.
 */
public enum class VaultTier(
    /**
     * True when the operating system's own credential store backs this tier
     * (Secret Service / Credential Manager / Keychain). These bind the secret to
     * the user's login session and encrypt it at rest under a key the JVM never
     * sees. False tiers offer obfuscation at best -- honest, not protective.
     */
    public val osBacked: Boolean,
) {
    /** Secret Service (Linux), Credential Manager / DPAPI (Windows), Keychain (macOS). */
    OsKeyring(true),

    /**
     * AES-256-GCM file. Obfuscation against a casual file copy, NOT protection
     * against a local attacker who can run code as this user (the key derives
     * from machine-local material they can also read). [SecretVault.secure] is
     * false for this tier.
     */
    SoftwareFile(false),

    /** In-process only; lost on exit. Opt-in (not in the default preference list). */
    Memory(false),

    /** Storage explicitly disabled. Every store is a no-op; nothing persists. */
    None(false),
}
