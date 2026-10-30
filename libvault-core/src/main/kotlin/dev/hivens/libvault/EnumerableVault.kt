package dev.hivens.libvault

/**
 * A [SecretVault] that can enumerate and bulk-wipe the keys in its namespace.
 * Discover with [asEnumerable]. Bounded like every other op; degrades to an empty
 * list / -1 on a backend fault rather than throwing.
 */
public interface EnumerableVault {
    /** Bare keys (namespace stripping done) currently stored. Empty on fault. */
    public fun list(): List<String>

    /**
     * Delete every key in this namespace. Returns the count actually removed, or
     * -1 if the operation could not be confirmed. Idempotent.
     */
    public fun clear(): Int
}
