package dev.hivens.libvault.internal

import dev.hivens.libvault.EnumerableVault
import dev.hivens.libvault.MigrationReport
import dev.hivens.libvault.SecretVault

/**
 * Shared [dev.hivens.libvault.MigratableVault.migrateTo] body: enumerate the
 * source, copy each secret into the target, optionally delete from the source
 * once the copy confirmed. Every migratable backend delegates here so the
 * read-write-delete logic lives in one place.
 */
internal object Migrator {

    fun migrate(source: SecretVault, target: SecretVault, deleteAfter: Boolean): MigrationReport {
        val keys = (source as? EnumerableVault)?.list().orEmpty()
        var copied = 0
        var deleted = 0
        val failures = mutableListOf<String>()
        for (key in keys) {
            val value = source.retrieve(key)
            if (value == null) {
                failures += key
                continue
            }
            val stored = try {
                target.store(key, value)
            } finally {
                value.fill(0)
            }
            if (!stored) {
                failures += key
                continue
            }
            copied++
            if (deleteAfter && source.delete(key)) deleted++
        }
        return MigrationReport(attempted = keys.size, copied = copied, deleted = deleted, failures = failures)
    }
}
