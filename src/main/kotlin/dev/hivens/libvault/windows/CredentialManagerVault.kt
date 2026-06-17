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
 * prefix segment in the target name (not a separately-lockable store).
 */
internal class CredentialManagerVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val bindings: Win32Bindings,
    namespace: String,
    collection: String?,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "credential-manager (DPAPI)"),
    EnumerableVault, DescribableVault, LabeledVault, UnlockableVault, WatchableVault, MigratableVault {

    private val prefix = prefixOf(namespace, collection)

    private fun target(key: String): String = "$prefix$key"
    private fun keyOf(target: String): String? = target.takeIf { it.startsWith(prefix) }?.removePrefix(prefix)

    override fun storeRaw(key: String, secret: ByteArray): Boolean = bindings.write(target(key), secret, null)

    override fun retrieveRaw(key: String): ByteArray? = bindings.read(target(key))

    override fun deleteRaw(key: String): Boolean =
        if (bindings.delete(target(key))) true else bindings.read(target(key)) == null

    override fun containsRaw(key: String): Boolean = bindings.read(target(key)) != null

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { bindings.write(target(key), secret, label) }
    }

    override fun list(): List<String> = bounded(emptyList()) {
        bindings.enumerate("$prefix*").mapNotNull { keyOf(it) }.filterNot { it == PROBE_KEY }
    }

    override fun clear(): Int = bounded(-1) {
        var removed = 0
        for (t in bindings.enumerate("$prefix*")) if (bindings.delete(t)) removed++
        removed
    }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null) {
            val meta = bindings.readMeta(target(key)) ?: return@bounded null
            EntryMetadata(
                label = meta.comment,
                created = null,
                modified = meta.lastWrittenMillis.takeIf { it > 0 }?.let { Instant.ofEpochMilli(it) },
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

        fun create(config: VaultConfig): ProbeResult {
            val executor = Executors.newSingleThreadExecutor { r ->
                Thread(r, "libvault-credman").apply { isDaemon = true }
            }
            val setup = try {
                executor.submit(
                    Callable {
                        val bindings = Win32Bindings.load() ?: return@Callable Setup.Unavailable(VaultAvailability.LibraryUnavailable)
                        val probe = prefixOf(config.namespace, config.collection) + PROBE_KEY
                        val ok = bindings.write(probe, PROBE_VALUE, null) &&
                            bindings.read(probe)?.contentEquals(PROBE_VALUE) == true
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
