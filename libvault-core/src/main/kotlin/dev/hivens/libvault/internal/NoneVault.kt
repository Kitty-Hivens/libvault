package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultTier

/**
 * [VaultTier.None] -- the guaranteed floor [Vault.open] returns when storage is
 * disabled or nothing else is reachable and the software fallback is off. Every
 * store is honestly reported as not persisted (false); retrieve/contains are
 * empty; delete is vacuously true. Never throws, never hangs.
 */
internal object NoneVault : SecretVault {

    override val tier: VaultTier = VaultTier.None
    override val backend: String = "none (disabled)"

    override fun store(key: String, secret: ByteArray): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return false
    }

    override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return null
    }

    override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return true
    }

    override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return false
    }

    override fun close() {}
}
