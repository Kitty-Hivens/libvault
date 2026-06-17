package dev.hivens.libvault

/**
 * Outcome of a [MigratableVault.migrateTo]. [copied] keys are now in the target;
 * [deleted] were removed from the source (only when `deleteAfter` was set);
 * [failures] lists keys that could not be read or written.
 */
public data class MigrationReport(
    public val attempted: Int,
    public val copied: Int,
    public val deleted: Int,
    public val failures: List<String>,
) {
    /** True when every attempted key copied and nothing failed. */
    public val complete: Boolean get() = failures.isEmpty() && copied == attempted
}
