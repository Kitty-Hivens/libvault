package dev.hivens.libvault.internal

import dev.hivens.libvault.DescribableVault
import dev.hivens.libvault.EntryMetadata
import dev.hivens.libvault.EnumerableVault
import dev.hivens.libvault.KeyDerivation
import dev.hivens.libvault.LabeledVault
import dev.hivens.libvault.MigratableVault
import dev.hivens.libvault.MigrationReport
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultTier
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.security.InvalidAlgorithmParameterException
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.withLock

/**
 * [VaultTier.SoftwareFile] -- a single AES-256-GCM file holding many records.
 *
 * File layout (big-endian):
 * ```
 * magic[4]="LVLT" version[1] kdfId[1]
 * saltLen[1] salt[saltLen]
 * verifierNonceLen[1] verifierNonce[..] verifierCtLen[4] verifierCt[..]
 * recordCount[4]
 *   v1 record: keyUTF, nonceLen[1] nonce[..], ctLen[4] ct[..]
 *   v2 record: ... + createdMillis[8] modifiedMillis[8] hasLabel[1] [labelUTF]
 *              attrCount[2] (keyUTF valUTF)*
 * ```
 * The verifier is a fixed plaintext encrypted under the file's key. Decrypting
 * it proves the key this vault holds is the one the file was written with. Each
 * record's ciphertext is bound to its key via GCM AAD. Always serialized as v2,
 * v1 files are still read (metadata defaults to unknown).
 *
 * Several vaults may share the file, in this process or in others. Writes take
 * an exclusive lock on a sibling `.lock` file, reread the file under it, and
 * replace it atomically (temp + rename), so a reader always sees one whole
 * version and no writer loses another's records. Every operation rereads the
 * file when it changed on disk since this vault last looked.
 *
 * A file this vault cannot read (wrong passphrase, changed machine material,
 * corrupt, or a newer format) is never overwritten. Reads report nothing, and
 * the first write moves the file aside to `<name>.unreadable-<UTC time>` before
 * starting a new one, so the old secrets stay recoverable with the right key.
 *
 * A failure that says nothing about the file (an I/O error, a key source that
 * did not answer) fails the operation and changes nothing: the next operation
 * reads the file again. Only a file that parses wrong, a key the source no
 * longer has, or a verifier that fails its GCM tag makes the file unreadable.
 *
 * [secure] is false: this tier is obfuscation, not protection. Operations are
 * local and synchronous. Waiting for this vault's own lock and for another
 * writer's file lock is bounded, by [lockTimeoutMs].
 */
internal class SoftwareFileVault private constructor(
    private val path: Path,
    private val fileKey: FileKey,
    private val lockTimeoutMs: Long,
) : SecretVault, EnumerableVault, DescribableVault, LabeledVault, MigratableVault {

    override val tier: VaultTier = VaultTier.SoftwareFile
    override val backend: String = "aes-256-gcm file"

    private val log = LoggerFactory.getLogger(SoftwareFileVault::class.java)
    private val lock = ReentrantLock()
    private val lockPath: Path = path.resolveSibling("${path.fileName}.lock")
    private var closed = false

    // The file as last read. `loaded` false forces the next refresh to read it.
    // Touched only while holding [lock].
    private var loaded = false
    private var seen: FileStamp? = null
    private var header: Header? = null
    private var key: SecretKey? = null
    private var unreadable = false
    private val records = LinkedHashMap<String, Record>()

    private class Header(val kdfId: Int, val salt: ByteArray, val verifierNonce: ByteArray, val verifierCt: ByteArray)

    private class Record(
        val nonce: ByteArray,
        val ct: ByteArray,
        val createdMillis: Long,
        val modifiedMillis: Long,
        val label: String?,
        val attributes: Map<String, String>,
    )

    /** What identifies one version of the file on disk. A rename gives a new file key on POSIX. */
    private data class FileStamp(val modified: FileTime, val size: Long, val fileKey: Any?)

    override fun store(key: String, secret: ByteArray): Boolean = putRecord(key, secret, null, emptyMap())

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean =
        putRecord(key, secret, label, attributes)

    private fun putRecord(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return mutate(false) {
            if (unreadable && !setAside()) return@mutate false
            val k = this.key ?: startNewFile() ?: return@mutate false
            val (nonce, ct) = encrypt(k, secret, key.toByteArray(StandardCharsets.UTF_8))
            val now = System.currentTimeMillis()
            val created = records[key]?.createdMillis?.takeIf { it > 0 } ?: now
            records[key] = Record(nonce, ct, created, now, label, attributes.toMap())
            persist()
        }
    }

    override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return read(null) {
            val k = this.key ?: return@read null
            val record = records[key] ?: return@read null
            decrypt(k, record.nonce, record.ct, key.toByteArray(StandardCharsets.UTF_8))
        }
    }

    override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return mutate(false) {
            // An unreadable file belongs to whoever holds its key. There is
            // nothing of ours in it to delete, and no right to rewrite it.
            if (unreadable) return@mutate true
            val removed = records.remove(key) ?: return@mutate true
            removed.ct.fill(0)
            persist()
        }
    }

    override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return read(false) { !unreadable && records.containsKey(key) }
    }

    override fun list(): List<String> = read(emptyList()) { if (unreadable) emptyList() else records.keys.toList() }

    override fun clear(): Int = mutate(-1) {
        if (unreadable) return@mutate 0
        val count = records.size
        if (count == 0) return@mutate 0
        for (r in records.values) r.ct.fill(0)
        records.clear()
        if (persist()) count else -1
    }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return read(null) {
            if (unreadable) return@read null
            val r = records[key] ?: return@read null
            EntryMetadata(
                label = r.label,
                created = r.createdMillis.takeIf { it > 0 }?.let { Instant.ofEpochMilli(it) },
                modified = r.modifiedMillis.takeIf { it > 0 }?.let { Instant.ofEpochMilli(it) },
                attributes = r.attributes,
            )
        }
    }

    override fun migrateTo(target: SecretVault, deleteAfter: Boolean): MigrationReport =
        Migrator.migrate(this, target, deleteAfter)

    override fun close() {
        // Unbounded on purpose, but whoever holds the lock gives it up within
        // its own bounded wait.
        lock.withLock {
            closed = true
            fileKey.close()
            key = null
            header = null
            records.clear()
        }
    }

    // ── Access ────────────────────────────────────────────────────────────────

    /**
     * A failure that says nothing about the file: an I/O error, a key source
     * that threw. The operation fails, the in-memory state is dropped, and the
     * next operation reads the file again.
     */
    private class TransientFailure(message: String, cause: Throwable? = null) : Exception(message, cause)

    private fun deadline(): Long = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(lockTimeoutMs)

    private fun remainingMs(deadline: Long): Long =
        TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).coerceAtLeast(0)

    /** Take this vault's lock by [deadline]. False on timeout or interrupt. */
    private fun lockBy(deadline: Long): Boolean = try {
        lock.tryLock(remainingMs(deadline), TimeUnit.MILLISECONDS).also {
            if (!it) log.warn("software vault at {} is busy in this vault, gave up after {} ms", path, lockTimeoutMs)
        }
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    /** [refresh], reporting a [TransientFailure] as false after dropping the state. */
    private fun refreshed(): Boolean = try {
        refresh()
        true
    } catch (e: TransientFailure) {
        log.warn("software vault at {} could not be read: {}", path, e.cause?.message ?: e.message)
        loaded = false
        false
    }

    /**
     * A read needs no file lock: writers replace the file by rename, so the
     * bytes read are always one whole version.
     */
    private inline fun <T> read(failure: T, block: () -> T): T {
        if (!lockBy(deadline())) return failure
        try {
            if (closed || !refreshed()) return failure
            return guarded(failure, block)
        } finally {
            lock.unlock()
        }
    }

    /**
     * A write holds the file lock across reread, change and replace, so a
     * record another process wrote in between is kept. It always rereads: the
     * file stamp misses a change of the same size within one timestamp tick,
     * and on Windows it carries no file key to tell a replaced file apart. If
     * the new version does not land, the in-memory state is dropped and the
     * next call reads the file again rather than trusting what failed to reach
     * it.
     */
    private inline fun <T> mutate(failure: T, crossinline block: () -> T): T {
        val deadline = deadline()
        if (!lockBy(deadline)) return failure
        try {
            if (closed) return failure
            return holdingFileLock(failure, deadline) {
                loaded = false
                if (!refreshed()) return@holdingFileLock failure
                val result = guarded(failure, block)
                if (result == failure) loaded = false
                result
            }
        } finally {
            lock.unlock()
        }
    }

    /** Run [block], turning anything it throws into [failure]: nothing escapes a vault operation. */
    private inline fun <T> guarded(failure: T, block: () -> T): T = try {
        block()
    } catch (e: Exception) {
        log.warn("software vault operation at {} failed: {}", path, e.message ?: e.javaClass.simpleName)
        loaded = false
        failure
    }

    private inline fun <T> holdingFileLock(failure: T, deadline: Long, block: () -> T): T {
        val inProcess = PROCESS_LOCKS.computeIfAbsent(lockPath.toAbsolutePath().normalize()) { ReentrantLock() }
        try {
            // A FileLock is held per process, so two vaults of this process on
            // one file exclude each other here, before either asks the OS.
            if (!inProcess.tryLock(remainingMs(deadline), TimeUnit.MILLISECONDS)) {
                log.warn("software vault at {} is held by another vault in this process, gave up after {} ms", path, lockTimeoutMs)
                return failure
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            return failure
        }
        try {
            path.parent?.let { Files.createDirectories(it) }
            FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
                var held: FileLock? = tryFileLock(channel)
                while (held == null) {
                    if (System.nanoTime() >= deadline) {
                        log.warn("software vault at {} is held by another process, gave up after {} ms", path, lockTimeoutMs)
                        return failure
                    }
                    Thread.sleep(LOCK_RETRY_MS)
                    held = tryFileLock(channel)
                }
                try {
                    return block()
                } finally {
                    held.release()
                }
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            return failure
        } catch (e: IOException) {
            log.warn("software vault lock at {} failed: {}", lockPath, e.message)
            return failure
        } finally {
            inProcess.unlock()
        }
    }

    /**
     * The OS lock, or null while someone else holds it. The JVM keeps one lock
     * table per file, so a vault of this process that reached the same file by
     * another path (a symlink, another letter case) shows up here as an
     * overlap, which is held all the same.
     */
    private fun tryFileLock(channel: FileChannel): FileLock? = try {
        channel.tryLock()
    } catch (e: OverlappingFileLockException) {
        null
    }

    // ── Load ──────────────────────────────────────────────────────────────────

    /**
     * Bring the in-memory state up to the file on disk, reading it only when it
     * changed. The state is replaced only once the file has been read to an
     * answer: absent, unreadable, or open. A [TransientFailure] leaves no
     * answer and is thrown to the caller.
     */
    private fun refresh() {
        val stamp = stampOf(path)
        if (loaded && stamp == seen) return
        loaded = false
        if (stamp == null) return settle(stamp)

        val bytes = try {
            Files.readAllBytes(path)
        } catch (e: NoSuchFileException) {
            return settle(null)
        } catch (e: IOException) {
            throw TransientFailure("read failed", e)
        }
        val parsed = parse(bytes)
        if (parsed == null) {
            log.warn("software vault at {} is corrupt or in an unknown format, it will be moved aside on the next write", path)
            return settle(stamp, unreadable = true)
        }
        val (header, records) = parsed
        val k = if (header.kdfId == fileKey.kdfId) {
            try {
                fileKey.keyFor(header.salt)
            } catch (e: Exception) {
                throw TransientFailure("key source failed", e)
            }
        } else {
            null
        }
        if (k == null || !verifies(k, header)) {
            log.info("software vault at {} does not open under the current key, it will be moved aside on the next write", path)
            return settle(stamp, unreadable = true)
        }
        settle(stamp, header = header, key = k, records = records)
    }

    private fun settle(
        stamp: FileStamp?,
        unreadable: Boolean = false,
        header: Header? = null,
        key: SecretKey? = null,
        records: Map<String, Record> = emptyMap(),
    ) {
        this.seen = stamp
        this.unreadable = unreadable
        this.header = header
        this.key = key
        this.records.clear()
        this.records.putAll(records)
        this.loaded = true
    }

    /**
     * Whether [k] opens the file's verifier. Only a failed GCM tag, or
     * parameters the file itself got wrong, answer no. Anything else is the
     * key source failing, not the key being wrong.
     */
    private fun verifies(k: SecretKey, h: Header): Boolean {
        val proof = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(GCM_TAG_BITS, h.verifierNonce))
            cipher.updateAAD(VERIFIER_AAD)
            cipher.doFinal(h.verifierCt)
        } catch (e: AEADBadTagException) {
            return false
        } catch (e: InvalidAlgorithmParameterException) {
            return false
        } catch (e: Exception) {
            throw TransientFailure("verifier check failed", e)
        }
        return proof.contentEquals(VERIFIER_PLAINTEXT)
    }

    private fun parse(bytes: ByteArray): Pair<Header, Map<String, Record>>? = runCatching {
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val magic = ByteArray(MAGIC.size)
            input.readFully(magic)
            if (!magic.contentEquals(MAGIC)) return null
            val version = input.readUnsignedByte()
            if (version != VERSION_1 && version != VERSION_2) return null
            val kdfId = input.readUnsignedByte()
            val salt = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
            val verifierNonce = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
            val verifierCt = readSized(input)
            val parsed = LinkedHashMap<String, Record>()
            repeat(input.readInt()) {
                val k = input.readUTF()
                val nonce = ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
                val ct = readSized(input)
                parsed[k] = if (version >= VERSION_2) {
                    val created = input.readLong()
                    val modified = input.readLong()
                    val label = if (input.readBoolean()) input.readUTF() else null
                    Record(nonce, ct, created, modified, label, readAttributes(input))
                } else {
                    Record(nonce, ct, 0, 0, null, emptyMap())
                }
            }
            Header(kdfId, salt, verifierNonce, verifierCt) to parsed
        }
    }.getOrNull()

    // ── Unreadable files and new files ────────────────────────────────────────

    /** Move an unreadable file out of the way, keeping it for whoever holds its key. */
    private fun setAside(): Boolean {
        val stamp = ASIDE_TIME.format(Instant.now())
        var target = path.resolveSibling("${path.fileName}.unreadable-$stamp")
        var n = 1
        while (Files.exists(target)) target = path.resolveSibling("${path.fileName}.unreadable-$stamp-${n++}")
        try {
            Files.move(path, target)
        } catch (e: NoSuchFileException) {
            // Gone already, which is all this wanted.
        } catch (e: IOException) {
            log.warn("software vault at {} cannot be read and could not be moved aside: {}", path, e.message)
            return false
        }
        log.warn("software vault at {} cannot be read with the current key, moved it to {} and starting a new one", path, target)
        unreadable = false
        seen = null
        return true
    }

    /** Fresh salt, key and verifier for a vault with no file yet. Null when the key source is unavailable. */
    private fun startNewFile(): SecretKey? {
        val salt = ByteArray(fileKey.saltLength).also { RANDOM.nextBytes(it) }
        val k = runCatching { fileKey.newKey(salt) }.getOrElse {
            log.warn("software vault key could not be created: {}", it.message)
            return null
        }
        val (vn, vc) = encrypt(k, VERIFIER_PLAINTEXT, VERIFIER_AAD)
        header = Header(fileKey.kdfId, salt, vn, vc)
        key = k
        records.clear()
        return k
    }

    // ── Persist (always v2) ───────────────────────────────────────────────────

    private fun persist(): Boolean {
        val out = runCatching { serialize() }.getOrElse {
            log.warn("software vault serialization failed: {}", it.message)
            return false
        }
        return try {
            val dir = path.toAbsolutePath().parent
            Files.createDirectories(dir)
            val tmp = Files.createTempFile(dir, ".vault", ".tmp")
            try {
                Files.write(tmp, out)
                try {
                    Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE)
                } catch (e: AtomicMoveNotSupportedException) {
                    Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                Files.deleteIfExists(tmp)
            }
            seen = stampOf(path)
            true
        } catch (e: IOException) {
            log.warn("software vault write failed at {}: {}", path, e.message)
            false
        }
    }

    private fun serialize(): ByteArray {
        val h = requireNotNull(header) { "cannot serialize before a header is established" }
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { out ->
            out.write(MAGIC)
            out.writeByte(VERSION_2)
            out.writeByte(h.kdfId)
            out.writeByte(h.salt.size)
            out.write(h.salt)
            out.writeByte(h.verifierNonce.size)
            out.write(h.verifierNonce)
            out.writeInt(h.verifierCt.size)
            out.write(h.verifierCt)
            out.writeInt(records.size)
            for ((k, record) in records) {
                out.writeUTF(k)
                out.writeByte(record.nonce.size)
                out.write(record.nonce)
                out.writeInt(record.ct.size)
                out.write(record.ct)
                out.writeLong(record.createdMillis)
                out.writeLong(record.modifiedMillis)
                out.writeBoolean(record.label != null)
                record.label?.let { out.writeUTF(it) }
                writeAttributes(out, record.attributes)
            }
        }
        return buffer.toByteArray()
    }

    private fun writeAttributes(out: DataOutputStream, attrs: Map<String, String>) {
        out.writeShort(attrs.size)
        for ((k, v) in attrs) {
            out.writeUTF(k)
            out.writeUTF(v)
        }
    }

    private fun readAttributes(input: DataInputStream): Map<String, String> {
        val n = input.readUnsignedShort()
        if (n == 0) return emptyMap()
        val out = LinkedHashMap<String, String>(n)
        repeat(n) { out[input.readUTF()] = input.readUTF() }
        return out
    }

    // ── AES-256-GCM ───────────────────────────────────────────────────────────

    /**
     * The cipher picks the nonce. A key held in a hardware keystore refuses a
     * caller-supplied one, and the JDK provider draws it from a SecureRandom.
     */
    private fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        return cipher.iv to ct
    }

    private fun decrypt(key: SecretKey, nonce: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray? =
        runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(ct)
        }.getOrNull()

    private fun readSized(input: DataInputStream): ByteArray = ByteArray(input.readInt()).also { input.readFully(it) }

    companion object {
        private val MAGIC = byteArrayOf('L'.code.toByte(), 'V'.code.toByte(), 'L'.code.toByte(), 'T'.code.toByte())
        private const val VERSION_1 = 1
        private const val VERSION_2 = 2
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val LOCK_RETRY_MS = 20L
        private val VERIFIER_PLAINTEXT = "libvault-verifier-v1".toByteArray(StandardCharsets.UTF_8)
        private val VERIFIER_AAD = "verifier".toByteArray(StandardCharsets.UTF_8)
        private val RANDOM = SecureRandom()
        private val ASIDE_TIME: DateTimeFormatter =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC)

        /** One lock per file across every vault in this process, keyed by the lock file's path. */
        private val PROCESS_LOCKS = ConcurrentHashMap<Path, ReentrantLock>()

        /** The file's stamp, or null when there is no file. Any other failure is not an answer. */
        private fun stampOf(path: Path): FileStamp? = try {
            val attrs = Files.readAttributes(path, BasicFileAttributes::class.java)
            FileStamp(attrs.lastModifiedTime(), attrs.size(), attrs.fileKey())
        } catch (e: NoSuchFileException) {
            null
        } catch (e: IOException) {
            throw TransientFailure("stat failed", e)
        }

        fun open(path: Path, keyDerivation: KeyDerivation, lockTimeoutMs: Long): SoftwareFileVault =
            open(path, DerivedFileKey(keyDerivation), lockTimeoutMs)

        fun open(path: Path, fileKey: FileKey, lockTimeoutMs: Long): SoftwareFileVault =
            SoftwareFileVault(path, fileKey, lockTimeoutMs).also { vault ->
                // Read once now, so a file that does not open is reported when
                // the vault opens rather than on its first use.
                vault.lock.withLock { vault.refreshed() }
            }
    }
}
