package dev.hivens.libvault.windows

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
import dev.hivens.libvault.internal.Migrator
import dev.hivens.libvault.internal.ProbeResult
import dev.hivens.libvault.internal.SingleThreadVault
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * [VaultTier.OsKeyring] on Windows -- Credential Manager via [Win32Bindings].
 * Each entry is DPAPI-encrypted, bound to this Windows user on this machine.
 *
 * Capabilities: enumerate, describe (label from Comment, modified from
 * LastWritten -- Windows has no creation time), labeled store. Credential Manager
 * unlocks with the interactive logon session, so [isLocked] is false and
 * [unlock]/[lock] are no-ops; there is no external change feed, so [onWatch]
 * returns an inert subscription. A [VaultConfig.collection] becomes a logical
 * prefix segment in the target name (not a separately-lockable store), and the
 * credential's UserName records which scope wrote it.
 */
internal class CredentialManagerVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val bindings: Win32Bindings,
    namespace: String,
    private val collection: String?,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "credential-manager (DPAPI)"),
    EnumerableVault, DescribableVault, LabeledVault, UnlockableVault, WatchableVault, MigratableVault {

    private val namespacePrefix = "$namespace/"
    private val prefix = prefixOf(namespace, collection)
    private val owner = ownerOf(collection)

    private fun target(key: String): String = "$prefix$key"
    private fun keyOf(target: String): String? = target.takeIf { it.startsWith(prefix) }?.removePrefix(prefix)

    /**
     * Whether an operation on one exact key may use the credential at its
     * target. The prefix alone cannot say whose it is: the default vault's key
     * `work/k` and the `work` collection's key `k` share the target `ns/work/k`.
     * The UserName written beside every entry settles it.
     *
     * An entry written before the UserName was set carries an empty one and
     * belongs to nobody yet. The caller named the key in full, so it is used as
     * it always was, and a store claims it.
     */
    private fun mayUse(userName: String): Boolean = userName == owner || userName.isEmpty()

    /**
     * Whether [list] and [clear] count the credential as this vault's. They
     * have no key to go by, so an entry nobody has claimed is read one fixed
     * way, a slash after the namespace meaning a collection, and no two vaults
     * ever list or clear the same entry.
     */
    private fun enumerates(target: String, userName: String): Boolean {
        if (userName == owner) return true
        if (userName.isNotEmpty() || !target.startsWith(namespacePrefix)) return false
        val rest = target.removePrefix(namespacePrefix)
        val legacyCollection = rest.substringBefore('/', missingDelimiterValue = "").ifEmpty { null }
        return legacyCollection == collection
    }

    private fun readOwned(key: String, withSecret: Boolean): Win32Bindings.Credential? {
        val cred = bindings.read(target(key), withSecret) ?: return null
        if (mayUse(cred.userName)) return cred
        cred.blob?.fill(0)
        return null
    }

    private fun write(key: String, secret: ByteArray, label: String?): Boolean {
        val t = target(key)
        // The target may hold another scope's entry. Overwriting it would
        // destroy that scope's secret, so the write is refused instead.
        val existing = bindings.read(t, withSecret = false)
        if (existing != null && !mayUse(existing.userName)) {
            log.warn("credential-manager: '{}' belongs to another libvault scope, not overwriting it", t)
            return false
        }
        return bindings.write(t, secret, label, owner)
    }

    private fun ownedKeys(): List<Pair<String, String>> =
        bindings.enumerate("$prefix*").mapNotNull { listed ->
            val key = keyOf(listed.target) ?: return@mapNotNull null
            if (enumerates(listed.target, listed.userName)) listed.target to key else null
        }

    override fun storeRaw(key: String, secret: ByteArray): Boolean = write(key, secret, null)

    override fun retrieveRaw(key: String): ByteArray? = readOwned(key, withSecret = true)?.blob

    override fun deleteRaw(key: String): Boolean {
        if (readOwned(key, withSecret = false) == null) return true
        return if (bindings.delete(target(key))) true else bindings.read(target(key), withSecret = false) == null
    }

    override fun containsRaw(key: String): Boolean = readOwned(key, withSecret = false) != null

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { write(key, secret, label) }
    }

    override fun list(): List<String> = bounded(emptyList()) {
        ownedKeys().map { it.second }.filterNot { it == PROBE_KEY }
    }

    override fun clear(): Int = bounded(-1) {
        var removed = 0
        for ((t, _) in ownedKeys()) if (bindings.delete(t)) removed++
        removed
    }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null) {
            val cred = readOwned(key, withSecret = false) ?: return@bounded null
            EntryMetadata(
                label = cred.comment,
                created = null,
                modified = cred.lastWrittenMillis.takeIf { it > 0 }?.let { Instant.ofEpochMilli(it) },
                attributes = emptyMap(),
            )
        }
    }

    override fun isLocked(): Boolean = false
    override fun unlock(): Boolean = true
    override fun lock(): Boolean = true
    override fun onWatch(callback: (VaultChange) -> Unit): AutoCloseable = AutoCloseable {}

    override fun migrateTo(target: SecretVault, deleteAfter: Boolean): MigrationReport =
        Migrator.migrate(this, target, deleteAfter)

    override fun cleanupRaw() {
        bindings.close()
    }

    private sealed interface Setup {
        data class Ready(val bindings: Win32Bindings) : Setup
        data class Unavailable(val availability: VaultAvailability) : Setup
    }

    companion object {
        private val log = LoggerFactory.getLogger(CredentialManagerVault::class.java)
        private const val PROBE_KEY = "__libvault_probe__"
        private val PROBE_VALUE = "ok".toByteArray(StandardCharsets.UTF_8)

        private fun prefixOf(namespace: String, collection: String?): String =
            if (collection != null) "$namespace/$collection/" else "$namespace/"

        private fun ownerOf(collection: String?): String =
            if (collection != null) "libvault:$collection" else "libvault"

        fun create(config: VaultConfig): ProbeResult {
            val executor = Executors.newSingleThreadExecutor { r ->
                Thread(r, "libvault-credman").apply { isDaemon = true }
            }
            val setup = try {
                executor.submit(
                    Callable {
                        val bindings = Win32Bindings.load() ?: return@Callable Setup.Unavailable(VaultAvailability.LibraryUnavailable)
                        val probe = prefixOf(config.namespace, config.collection) + PROBE_KEY
                        val ok = bindings.write(probe, PROBE_VALUE, null, ownerOf(config.collection)) &&
                            bindings.read(probe, withSecret = true)?.blob?.contentEquals(PROBE_VALUE) == true
                        if (ok) {
                            bindings.delete(probe)
                            Setup.Ready(bindings)
                        } else {
                            bindings.close()
                            Setup.Unavailable(VaultAvailability.ServiceUnavailable)
                        }
                    },
                ).get(config.probeTimeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                log.info("credential-manager setup failed: {}", e.message ?: e.javaClass.simpleName)
                executor.shutdownNow()
                return ProbeResult.Unavailable(VaultAvailability.ServiceUnavailable)
            }
            return when (setup) {
                is Setup.Ready ->
                    ProbeResult.Opened(CredentialManagerVault(executor, config.opTimeoutMs, setup.bindings, config.namespace, config.collection))
                is Setup.Unavailable -> {
                    executor.shutdownNow()
                    ProbeResult.Unavailable(setup.availability)
                }
            }
        }
    }
}
