package dev.hivens.libvault.android

import dev.hivens.libvault.DescribableVault
import dev.hivens.libvault.EntryMetadata
import dev.hivens.libvault.EnumerableVault
import dev.hivens.libvault.LabeledVault
import dev.hivens.libvault.MigratableVault
import dev.hivens.libvault.MigrationReport
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.UnlockableVault
import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultChange
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.WatchableVault
import dev.hivens.libvault.internal.EncryptedFileVault
import dev.hivens.libvault.internal.Migrator
import dev.hivens.libvault.internal.ProbeResult
import dev.hivens.libvault.internal.SingleThreadVault
import org.slf4j.LoggerFactory
import java.io.File
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * [VaultTier.OsKeyring] on Android: records in an [EncryptedFileVault] whose key
 * is a non-exportable AES key in the Android Keystore ([KeystoreFileKey]). The
 * file sits in the app's no-backup directory, so it never reaches a cloud
 * backup, where it would arrive without its key anyway.
 *
 * Every Keystore call crosses into a system service, so the vault runs on its
 * own thread behind [SingleThreadVault] and each op is bounded by
 * [VaultConfig.opTimeoutMs] like the desktop keyrings. Keystore keys made here
 * need no user authentication, so the store is never locked: [isLocked] is
 * false and [unlock]/[lock] are no-ops. There is no change feed, [onWatch] is
 * inert. [VaultConfig.accessibility] does not apply: the file lives in
 * credential-encrypted storage, readable from the first unlock after boot. A
 * [VaultConfig.collection] gets its own key and its own file.
 */
internal class KeystoreVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val file: EncryptedFileVault,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, BACKEND),
    EnumerableVault, DescribableVault, LabeledVault, UnlockableVault, WatchableVault, MigratableVault {

    override fun storeRaw(key: String, secret: ByteArray): Boolean = file.store(key, secret)

    override fun retrieveRaw(key: String): ByteArray? = file.retrieve(key)

    override fun deleteRaw(key: String): Boolean = file.delete(key)

    override fun containsRaw(key: String): Boolean = file.contains(key)

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { file.store(key, secret, label, attributes) }
    }

    override fun list(): List<String> = bounded(emptyList()) { file.list() }

    override fun clear(): Int = bounded(-1) { file.clear() }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null) { file.describe(key) }
    }

    override fun isLocked(): Boolean = false
    override fun unlock(): Boolean = true
    override fun lock(): Boolean = true
    override fun onWatch(callback: (VaultChange) -> Unit): AutoCloseable = AutoCloseable {}

    override fun migrateTo(target: SecretVault, deleteAfter: Boolean): MigrationReport =
        Migrator.migrate(this, target, deleteAfter)

    override fun cleanupRaw() {
        file.close()
    }

    internal companion object {
        const val BACKEND = "android-keystore (AES-GCM)"

        private val log = LoggerFactory.getLogger(KeystoreVault::class.java)
        private val PROBE_VALUE = "libvault-probe".toByteArray(StandardCharsets.UTF_8)

        /** The Keystore alias for a namespace and optional collection. */
        fun aliasOf(namespace: String, collection: String?): String =
            bounded(if (collection != null) "libvault/$namespace/$collection" else "libvault/$namespace")

        /** The directory holding a namespace's files under the app's no-backup directory. */
        fun namespaceDir(noBackupDir: File, namespace: String): File =
            File(File(noBackupDir, "libvault"), fileSafe(namespace))

        fun fileOf(noBackupDir: File, namespace: String, collection: String?): File =
            File(namespaceDir(noBackupDir, namespace), if (collection != null) "keystore-${fileSafe(collection)}.bin" else "keystore.bin")

        /** A name usable as one path segment: no separator, never `.` or `..`, never too long. */
        private fun fileSafe(name: String): String {
            val encoded = URLEncoder.encode(name, "UTF-8").replace("*", "%2A")
            return bounded(if (encoded.all { it == '.' }) encoded.replace(".", "%2E") else encoded)
        }

        /**
         * [name] itself while it is short, and its SHA-256 otherwise. A file
         * name stops at 255 bytes, and URL-encoding makes a non-ASCII name nine
         * times longer. The `~` cannot come out of URLEncoder, so a hashed name
         * never equals an encoded one.
         */
        private fun bounded(name: String): String {
            if (name.length <= MAX_NAME) return name
            val digest = MessageDigest.getInstance("SHA-256").digest(name.toByteArray(StandardCharsets.UTF_8))
            return "~" + digest.joinToString("") { "%02x".format(it) }
        }

        fun create(noBackupDir: File, config: VaultConfig): ProbeResult {
            val alias = aliasOf(config.namespace, config.collection)
            val path = fileOf(noBackupDir, config.namespace, config.collection).toPath()
            val executor = Executors.newSingleThreadExecutor { r ->
                Thread(r, "libvault-keystore").apply { isDaemon = true }
            }
            val opened = try {
                executor.submit(
                    Callable {
                        if (!keystoreWorks(alias)) return@Callable null
                        EncryptedFileVault.open(path, KeystoreFileKey(alias), config.opTimeoutMs, VaultTier.OsKeyring, BACKEND)
                    },
                ).get(config.probeTimeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                executor.shutdownNow()
                return ProbeResult.Unavailable(VaultAvailability.ServiceUnavailable)
            } catch (e: Exception) {
                log.info("android keystore setup failed: {}", e.message ?: e.javaClass.simpleName)
                executor.shutdownNow()
                return ProbeResult.Unavailable(VaultAvailability.ServiceUnavailable)
            }
            if (opened == null) {
                executor.shutdownNow()
                return ProbeResult.Unavailable(VaultAvailability.ServiceUnavailable)
            }
            return ProbeResult.Opened(KeystoreVault(executor, config.opTimeoutMs, opened))
        }

        /**
         * A Keystore that loads but cannot encrypt exists on real devices, so
         * the check is a round trip, held in memory: nothing is written to disk
         * to find out. It uses the vault's key when there is one. Otherwise it
         * makes a key of its own and removes it, because the vault's key is
         * made by its first write, under the file lock: two processes opening
         * at once cannot each make one and replace the other's, and a probe
         * leaves no key behind.
         */
        private fun keystoreWorks(alias: String): Boolean {
            val keyStore = KeystoreFileKey.keyStore()
            (keyStore.getKey(alias, null) as? SecretKey)?.let { return roundTrips(it) }
            val probeAlias = "libvault-probe/${UUID.randomUUID()}"
            return try {
                roundTrips(KeystoreFileKey.generate(probeAlias))
            } finally {
                runCatching { keyStore.deleteEntry(probeAlias) }
            }
        }

        private fun roundTrips(key: SecretKey): Boolean {
            val encrypt = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
            val ct = encrypt.doFinal(PROBE_VALUE)
            val decrypt = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, encrypt.iv))
            }
            return decrypt.doFinal(ct).contentEquals(PROBE_VALUE)
        }

        private const val MAX_NAME = 128
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }
}
