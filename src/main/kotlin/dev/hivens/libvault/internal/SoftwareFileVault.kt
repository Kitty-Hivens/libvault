package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultTier
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * [VaultTier.SoftwareFile] -- a single AES-256-GCM file holding many records.
 *
 * File layout (big-endian):
 * ```
 * magic[4]="LVLT" version[1] kdfId[1]
 * saltLen[1] salt[saltLen]
 * verifierNonceLen[1] verifierNonce[..] verifierCtLen[4] verifierCt[..]
 * recordCount[4]
 *   repeated: keyUTF, nonceLen[1] nonce[..], ctLen[4] ct[..]
 * ```
 * The verifier is a fixed plaintext encrypted under the derived key; decrypting
 * it on open proves the key still matches (same passphrase / unchanged machine).
 * If it doesn't, the records are unreadable and the next [store] reinitializes
 * the file. Each record's ciphertext is bound to its key via GCM AAD, so a
 * record copied to another key fails authentication.
 *
 * Writes are atomic (temp file + rename). This tier is honest about being
 * obfuscation, not protection: [secure] is false. It is synchronous and never
 * times out -- it's the floor the keyring tiers fall back to, so it must always
 * answer.
 */
internal class SoftwareFileVault private constructor(
    private val path: Path,
    private val configKdfId: Int,
    private val passphrase: CharArray?,
) : SecretVault {

    override val tier: VaultTier = VaultTier.SoftwareFile
    override val backend: String = "aes-256-gcm file"

    private val log = LoggerFactory.getLogger(SoftwareFileVault::class.java)
    private val lock = Any()
    private val random = SecureRandom()

    private var salt: ByteArray? = null
    private var storedKdfId: Int = configKdfId
    private var verifierNonce: ByteArray? = null
    private var verifierCt: ByteArray? = null
    private var key: SecretKeySpec? = null
    private var verifierOk: Boolean = false
    private val records = LinkedHashMap<String, Record>()

    private class Record(val nonce: ByteArray, val ct: ByteArray)

    override fun store(key: String, secret: ByteArray): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        synchronized(lock) {
            ensureWritableKey()
            val k = this.key ?: return false
            val (nonce, ct) = encrypt(k, secret, key.toByteArray(StandardCharsets.UTF_8))
            records[key] = Record(nonce, ct)
            return persist()
        }
    }

    override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        synchronized(lock) {
            if (!verifierOk) return null
            val k = this.key ?: return null
            val record = records[key] ?: return null
            return decrypt(k, record.nonce, record.ct, key.toByteArray(StandardCharsets.UTF_8))
        }
    }

    override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        synchronized(lock) {
            val removed = records.remove(key) ?: return true // idempotent: nothing to delete
            removed.ct.fill(0)
            return if (records.isEmpty() && salt == null) true else persist()
        }
    }

    override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        synchronized(lock) { return verifierOk && records.containsKey(key) }
    }

    override fun close() {
        synchronized(lock) {
            passphrase?.fill(' ')
            key = null
            records.clear()
        }
    }

    // ── Key lifecycle ─────────────────────────────────────────────────────────

    /**
     * Guarantee [key] is set and matches the file. Initializes a fresh file, or
     * reinitializes one whose key no longer matches (passphrase or machine
     * changed) -- in the reinit case the old, now-unreadable records are dropped.
     */
    private fun ensureWritableKey() {
        if (key != null && verifierOk) return
        if (salt != null && records.isNotEmpty()) {
            log.warn(
                "software vault key no longer matches (passphrase or machine changed); " +
                    "dropping {} unreadable entr{}",
                records.size,
                if (records.size == 1) "y" else "ies",
            )
        }
        val newSalt = ByteArray(SALT_LEN).also { random.nextBytes(it) }
        val newKey = SecretKeySpec(deriveKey(newSalt), "AES")
        val (vn, vc) = encrypt(newKey, VERIFIER_PLAINTEXT, VERIFIER_AAD)
        salt = newSalt
        storedKdfId = configKdfId
        key = newKey
        verifierNonce = vn
        verifierCt = vc
        verifierOk = true
        records.clear()
    }

    private fun deriveKey(salt: ByteArray): ByteArray = when (configKdfId) {
        KdfEngine.KDF_PASSPHRASE ->
            KdfEngine.derivePassphrase(
                requireNotNull(passphrase) { "passphrase KDF selected without a passphrase" },
                salt,
            )
        else -> KdfEngine.deriveMachineBound(salt)
    }

    // ── Load ──────────────────────────────────────────────────────────────────

    private fun load() {
        synchronized(lock) {
            if (!Files.exists(path)) return
            val bytes = runCatching { Files.readAllBytes(path) }.getOrElse {
                log.warn("software vault unreadable at {}: {} -- will reinitialize on next write", path, it.message)
                return
            }
            if (!parse(bytes)) {
                log.warn("software vault at {} is corrupt or unrecognized -- will reinitialize on next write", path)
                resetParsedState()
                return
            }
            val derived = SecretKeySpec(deriveKey(salt!!), "AES")
            val proof = decrypt(derived, verifierNonce!!, verifierCt!!, VERIFIER_AAD)
            verifierOk = proof != null && proof.contentEquals(VERIFIER_PLAINTEXT)
            if (verifierOk) {
                key = derived
            } else {
                log.info("software vault at {} present but key mismatch -- entries not readable under current configuration", path)
            }
        }
    }

    private fun parse(bytes: ByteArray): Boolean = runCatching {
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val magic = ByteArray(MAGIC.size)
            input.readFully(magic)
            if (!magic.contentEquals(MAGIC)) return false
            if (input.readUnsignedByte() != VERSION) return false
            storedKdfId = input.readUnsignedByte()
            salt = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
            verifierNonce = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
            verifierCt = readSized(input)
            val count = input.readInt()
            repeat(count) {
                val k = input.readUTF()
                val nonce = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
                val ct = readSized(input)
                records[k] = Record(nonce, ct)
            }
        }
        true
    }.getOrElse { false }

    private fun resetParsedState() {
        salt = null
        verifierNonce = null
        verifierCt = null
        key = null
        verifierOk = false
        records.clear()
    }

    // ── Persist ─────────────────────────────────────────────────────────────────

    private fun persist(): Boolean {
        val out = runCatching { serialize() }.getOrElse {
            log.warn("software vault serialization failed: {}", it.message)
            return false
        }
        return try {
            path.parent?.let { Files.createDirectories(it) }
            val tmp = Files.createTempFile(path.parent ?: path.toAbsolutePath().parent, ".vault", ".tmp")
            Files.write(tmp, out)
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE)
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING)
            }
            true
        } catch (e: IOException) {
            log.warn("software vault write failed at {}: {}", path, e.message)
            false
        }
    }

    private fun serialize(): ByteArray {
        val saltBytes = requireNotNull(salt) { "cannot serialize before a salt is established" }
        val vn = requireNotNull(verifierNonce)
        val vc = requireNotNull(verifierCt)
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { out ->
            out.write(MAGIC)
            out.writeByte(VERSION)
            out.writeByte(storedKdfId)
            out.writeByte(saltBytes.size)
            out.write(saltBytes)
            out.writeByte(vn.size)
            out.write(vn)
            out.writeInt(vc.size)
            out.write(vc)
            out.writeInt(records.size)
            for ((k, record) in records) {
                out.writeUTF(k)
                out.writeByte(record.nonce.size)
                out.write(record.nonce)
                out.writeInt(record.ct.size)
                out.write(record.ct)
            }
        }
        return buffer.toByteArray()
    }

    // ── AES-256-GCM ─────────────────────────────────────────────────────────────

    private fun encrypt(key: SecretKeySpec, plaintext: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
        val nonce = ByteArray(GCM_NONCE_LEN).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return nonce to cipher.doFinal(plaintext)
    }

    private fun decrypt(key: SecretKeySpec, nonce: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray? =
        runCatching {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(ct)
        }.getOrNull()

    private fun readSized(input: DataInputStream): ByteArray = ByteArray(input.readInt()).also { input.readFully(it) }

    companion object {
        private val MAGIC = byteArrayOf('L'.code.toByte(), 'V'.code.toByte(), 'L'.code.toByte(), 'T'.code.toByte())
        private const val VERSION = 1
        private const val SALT_LEN = 16
        private const val GCM_NONCE_LEN = 12
        private const val GCM_TAG_BITS = 128
        private val VERIFIER_PLAINTEXT = "libvault-verifier-v1".toByteArray(StandardCharsets.UTF_8)
        private val VERIFIER_AAD = "verifier".toByteArray(StandardCharsets.UTF_8)

        /**
         * Open (and read, if present) the file at [path]. The [keyDerivation]'s
         * passphrase, if any, is copied so the caller may zero its own array
         * after [Vault.open]. Always returns a usable vault -- a missing or
         * corrupt file just means "no entries yet".
         */
        fun open(path: Path, keyDerivation: KeyDerivation): SoftwareFileVault {
            val passphraseCopy = (keyDerivation as? KeyDerivation.Passphrase)?.passphrase?.copyOf()
            return SoftwareFileVault(path, KdfEngine.kdfId(keyDerivation), passphraseCopy).also { it.load() }
        }
    }
}
