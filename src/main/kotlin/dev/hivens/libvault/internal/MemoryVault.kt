package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultTier
import java.util.concurrent.ConcurrentHashMap

/**
 * [VaultTier.Memory] -- secrets live in a process-local map and vanish on exit.
 * Opt-in (the default [dev.hivens.libvault.VaultConfig.preferredTiers] does not
 * list it). Useful for tests and for callers that deliberately want no
 * persistence. Defensive copies in and out so a caller mutating its array can't
 * reach into the store.
 */
internal class MemoryVault : SecretVault {

    override val tier: VaultTier = VaultTier.Memory
    override val backend: String = "memory (process-local)"

    private val entries = ConcurrentHashMap<String, ByteArray>()

    override fun store(key: String, secret: ByteArray): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        entries.put(key, secret.copyOf())?.fill(0)
        return true
    }

    override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return entries[key]?.copyOf()
    }

    override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        entries.remove(key)?.fill(0)
        return true
    }

    override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return entries.containsKey(key)
    }

    override fun close() {
        for (v in entries.values) v.fill(0)
        entries.clear()
    }
}
