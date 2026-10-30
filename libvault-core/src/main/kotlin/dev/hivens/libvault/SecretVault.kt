package dev.hivens.libvault

import dev.hivens.libvault.internal.SecretText

/**
 * A live, scoped secret store handed out by [Vault.open]. Every key passed to
 * its methods is implicitly namespaced (see [VaultConfig.namespace]); callers
 * pass bare keys like `"accessToken"`.
 *
 * Failure model -- nothing here throws on a backend fault:
 *   - [store] / [delete] return false when the operation did not confirm.
 *   - [retrieve] returns null when the key is absent OR the backend is
 *     unreachable; [contains] returns false in the same cases.
 *   - A blank [key] is a programming error and is rejected with
 *     `IllegalArgumentException` (the only thing these methods throw).
 *
 * Implementations are safe to call from any thread. OS-keyring backends serialize
 * work onto a single owned thread and bound each call by [VaultConfig.opTimeoutMs],
 * so a hung keyring service degrades instead of freezing the caller.
 */
public interface SecretVault : AutoCloseable {

    /** The tier this vault actually resolved to. */
    public val tier: VaultTier

    /** Human-readable backend label for diagnostics, e.g. `"secret-service (D-Bus)"`. */
    public val backend: String

    /** True when [tier] is OS-backed. Convenience over `tier.osBacked`. */
    public val secure: Boolean get() = tier.osBacked

    /** Insert or replace the secret stored under [key]. Returns confirmed success. */
    public fun store(key: String, secret: ByteArray): Boolean

    /** Read the secret under [key], or null when absent or unreachable. */
    public fun retrieve(key: String): ByteArray?

    /** Remove [key]. Idempotent -- nothing-to-delete still returns true. */
    public fun delete(key: String): Boolean

    /** True when [key] currently resolves to a retrievable secret. */
    public fun contains(key: String): Boolean

    /**
     * [store] a text secret without it ever existing as an immutable [String].
     * The caller should zero [secret] after this returns; the UTF-8 copy this
     * method makes internally is zeroed before it returns.
     */
    public fun storeString(key: String, secret: CharArray): Boolean {
        val bytes = SecretText.toUtf8(secret)
        return try {
            store(key, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * [retrieve] a text secret as a [CharArray] (never an interned [String]).
     * Returns null when absent or unreachable. The caller owns the result and
     * should zero it when done.
     */
    public fun retrieveString(key: String): CharArray? {
        val bytes = retrieve(key) ?: return null
        return try {
            SecretText.fromUtf8(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /** Release backend resources (threads, native handles). Idempotent. */
    override fun close()
}
