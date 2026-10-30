package dev.hivens.libvault

/**
 * A read-only snapshot of what a tier WOULD resolve to, produced by [Vault.probe]
 * without opening a live vault. Lets a caller answer "is the keyring just locked
 * (offer unlock) or genuinely absent (don't)?" before committing.
 */
public data class VaultStatus(
    public val tier: VaultTier,
    public val backend: String,
    public val availability: VaultAvailability,
) {
    /** True only when [availability] is [VaultAvailability.Available]. */
    public val usable: Boolean get() = availability == VaultAvailability.Available

    /** Whether this tier, if opened, would be OS-backed. Convenience over `tier.osBacked`. */
    public val secure: Boolean get() = tier.osBacked
}
