package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Where an encrypted vault file gets its AES key. The file format and its
 * locking are the same whoever supplies the key, so the source is the only part
 * a new kind of key has to provide.
 */
@InternalLibvaultApi
public interface FileKey {
    /**
     * The header byte naming this source, one of the ids below. A file written
     * by a different source is unreadable under this one, and is recognised as
     * such without trying.
     */
    public val kdfId: Int

    /** Salt length for a new file, or 0 when the key does not derive from one. */
    public val saltLength: Int

    /** The key a file with [salt] was written under, or null when this source cannot produce it. */
    public fun keyFor(salt: ByteArray): SecretKey?

    /** The key for a new file with [salt]. May replace whatever key the source held before. */
    public fun newKey(salt: ByteArray): SecretKey

    /** Forget any key material held in memory. Called once, when the vault closes. */
    public fun close()

    /** Header ids, allocated here so no two sources ever share one. Written to disk, never renumbered. */
    public companion object {
        public const val MACHINE_BOUND: Int = 0
        public const val PASSPHRASE: Int = 1
        public const val ANDROID_KEYSTORE: Int = 2
    }
}

/**
 * A key derived from [KeyDerivation] material through [KdfEngine]. The
 * derivation is slow on purpose, so the last result is kept for as long as the
 * file keeps the same salt.
 */
internal class DerivedFileKey(derivation: KeyDerivation) : FileKey {

    override val kdfId: Int = KdfEngine.kdfId(derivation)
    override val saltLength: Int = SALT_LEN

    private var passphrase: CharArray? = (derivation as? KeyDerivation.Passphrase)?.passphrase?.copyOf()
    private var closed = false
    private var cachedSalt: ByteArray? = null
    private var cachedKey: SecretKey? = null

    override fun keyFor(salt: ByteArray): SecretKey? {
        if (closed) return null
        val cached = cachedKey
        if (cached != null && cachedSalt.contentEquals(salt)) return cached
        val raw = when (kdfId) {
            KdfEngine.KDF_PASSPHRASE -> KdfEngine.derivePassphrase(passphrase ?: return null, salt)
            else -> KdfEngine.deriveMachineBound(salt)
        }
        return try {
            SecretKeySpec(raw, "AES").also {
                cachedSalt = salt.copyOf()
                cachedKey = it
            }
        } finally {
            raw.fill(0)
        }
    }

    override fun newKey(salt: ByteArray): SecretKey =
        checkNotNull(keyFor(salt)) { "key source is closed" }

    override fun close() {
        closed = true
        passphrase?.fill('\u0000')
        passphrase = null
        cachedSalt = null
        cachedKey = null
    }

    private companion object {
        const val SALT_LEN = 16
    }
}
