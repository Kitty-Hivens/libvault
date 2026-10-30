package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Where an encrypted vault file gets its AES key. The file format and its
 * locking are the same whoever supplies the key, so the source is the only part
 * a new kind of key has to provide.
 */
internal interface FileKey {
    /**
     * The header byte naming this source. A file written by a different source
     * is unreadable under this one, and is recognised as such without trying.
     */
    val kdfId: Int

    /** Salt length for a new file, or 0 when the key does not derive from one. */
    val saltLength: Int

    /** The key a file with [salt] was written under, or null when this source cannot produce it. */
    fun keyFor(salt: ByteArray): SecretKey?

    /** The key for a new file with [salt]. May replace whatever key the source held before. */
    fun newKey(salt: ByteArray): SecretKey

    /** Forget any key material held in memory. Called once, when the vault closes. */
    fun close()
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
        passphrase?.fill(' ')
        passphrase = null
        cachedSalt = null
        cachedKey = null
    }

    private companion object {
        const val SALT_LEN = 16
    }
}
