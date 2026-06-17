package dev.hivens.libvault.internal

import dev.hivens.libvault.DescribableVault
import dev.hivens.libvault.EntryMetadata
import dev.hivens.libvault.EnumerableVault
import dev.hivens.libvault.LabeledVault
import dev.hivens.libvault.MigratableVault
import dev.hivens.libvault.MigrationReport
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultTier
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * [VaultTier.Memory] -- secrets live in a process-local map and vanish on exit.
 * Opt-in. Defensive copies in and out. Supports the read/enumerate/describe/label/
 * migrate capabilities (it is never locked and has no external change feed, so it
 * is not [dev.hivens.libvault.UnlockableVault] / [dev.hivens.libvault.WatchableVault]).
 */
internal class MemoryVault : SecretVault, EnumerableVault, DescribableVault, LabeledVault, MigratableVault {

    override val tier: VaultTier = VaultTier.Memory
    override val backend: String = "memory (process-local)"

    private class Entry(
        val secret: ByteArray,
        val label: String?,
        val attributes: Map<String, String>,
        val created: Instant,
        val modified: Instant,
    )

    private val entries = ConcurrentHashMap<String, Entry>()

    override fun store(key: String, secret: ByteArray): Boolean = put(key, secret, null, emptyMap())

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean =
        put(key, secret, label, attributes)

    private fun put(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        val now = Instant.now()
        val created = entries[key]?.created ?: now
        entries.put(key, Entry(secret.copyOf(), label, attributes.toMap(), created, now))?.secret?.fill(0)
        return true
    }

    override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return entries[key]?.secret?.copyOf()
    }

    override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        entries.remove(key)?.secret?.fill(0)
        return true
    }

    override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return entries.containsKey(key)
    }

    override fun list(): List<String> = entries.keys.toList()

    override fun clear(): Int {
        val count = entries.size
        for (e in entries.values) e.secret.fill(0)
        entries.clear()
        return count
    }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        val e = entries[key] ?: return null
        return EntryMetadata(e.label, e.created, e.modified, e.attributes)
    }

    override fun migrateTo(target: SecretVault, deleteAfter: Boolean): MigrationReport =
        Migrator.migrate(this, target, deleteAfter)

    override fun close() {
        for (e in entries.values) e.secret.fill(0)
        entries.clear()
    }
}
