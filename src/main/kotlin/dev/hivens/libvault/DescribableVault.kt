package dev.hivens.libvault

/**
 * A [SecretVault] that can return [EntryMetadata] for a key without exposing the
 * secret value. Discover with [asDescribable].
 */
public interface DescribableVault {
    /** Metadata for [key], or null when the key is absent or unreachable. */
    public fun describe(key: String): EntryMetadata?
}
