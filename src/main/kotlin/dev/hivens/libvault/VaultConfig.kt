package dev.hivens.libvault

import java.nio.file.Path

/**
 * Everything [Vault.open] needs to pick and build a backend. All fields have
 * defaults tuned for the common case (OS keyring, soft-file fallback, no
 * passphrase); a typical caller sets only [namespace].
 */
public data class VaultConfig(
    /**
     * Application identity that scopes every key. Maps to the Secret Service
     * `app` attribute, the Credential Manager target prefix, and the Keychain
     * service. Use a stable reverse-DNS id, e.g. `"dev.hivens.nexira"`. Two apps
     * with different namespaces never see each other's keys. Must be non-blank.
     */
    public val namespace: String,

    /**
     * Whether [Vault.open] may fall back to the [VaultTier.SoftwareFile] tier
     * when no OS keyring is reachable. False means "OS keyring or nothing" --
     * `open()` returns a [VaultTier.None] (or [VaultTier.Memory], if listed)
     * vault rather than writing secrets to an obfuscated file.
     */
    public val allowSoftwareFallback: Boolean = true,

    /**
     * Where the [VaultTier.SoftwareFile] tier keeps its encrypted blob. Null
     * resolves to an OS-appropriate per-user data directory under [namespace]
     * (e.g. `~/.local/share/<namespace>/vault.bin`).
     */
    public val softwareFilePath: Path? = null,

    /** How the software-file tier derives its AES key. Irrelevant to OS tiers. */
    public val keyDerivation: KeyDerivation = KeyDerivation.MachineBound,

    /**
     * Ceiling, in milliseconds, on backend selection. A locked or prompt-only
     * keyring that can't be opened within this budget is skipped, not waited on.
     */
    public val probeTimeoutMs: Long = 1500,

    /**
     * Ceiling, in milliseconds, on a single store/retrieve/delete/contains
     * against an OS keyring. An operation that overruns degrades to
     * false/null rather than blocking the caller. The software-file and memory
     * tiers are local and synchronous; this bound does not apply to them.
     */
    public val opTimeoutMs: Long = 2000,

    /**
     * Tiers to try, in order, during [Vault.open]. The first one that opens
     * wins. [VaultTier.Memory] and [VaultTier.None] are honored only when
     * listed here. The default tries the OS keyring, then the software file.
     */
    public val preferredTiers: List<VaultTier> = listOf(VaultTier.OsKeyring, VaultTier.SoftwareFile),
) {
    init {
        require(namespace.isNotBlank()) { "namespace must be non-blank" }
        require(probeTimeoutMs > 0) { "probeTimeoutMs must be positive" }
        require(opTimeoutMs > 0) { "opTimeoutMs must be positive" }
    }
}
