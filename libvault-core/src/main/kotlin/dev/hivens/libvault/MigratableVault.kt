package dev.hivens.libvault

/**
 * A [SecretVault] that can move its secrets into another vault -- e.g. file ->
 * keyring after an interactive unlock, or keyring -> file before disabling it.
 * Composed over enumerate + retrieve + [target] store; discover with [asMigratable].
 */
public interface MigratableVault {
    /**
     * Copy every key from this vault into [target]. With [deleteAfter], a key is
     * removed from this vault only after it copied successfully. Returns a
     * [MigrationReport]; never throws.
     */
    public fun migrateTo(target: SecretVault, deleteAfter: Boolean = false): MigrationReport
}
