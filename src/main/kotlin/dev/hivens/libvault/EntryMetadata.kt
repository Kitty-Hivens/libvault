package dev.hivens.libvault

import java.time.Instant

/**
 * Read-side metadata for a stored entry, from [DescribableVault.describe]. Every
 * field is nullable/empty-tolerant: a backend that cannot supply a particular
 * facet returns null for it rather than failing the whole call (Windows has no
 * creation time; the memory tier has no timestamps unless tracked; etc.).
 */
public data class EntryMetadata(
    /** Human-readable label shown in OS tools (seahorse, Keychain Access), if any. */
    public val label: String?,
    public val created: Instant?,
    public val modified: Instant?,
    /** Extra searchable attributes attached at store time (beyond the scoping ones). */
    public val attributes: Map<String, String>,
)
