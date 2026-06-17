package dev.hivens.libvault.macos

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
 * [VaultTier.OsKeyring] on macOS -- Keychain Services via [SecurityBindings].
 * `service` is the [VaultConfig.namespace] (with the optional collection folded
 * in as a suffix); `account` is the key. Capabilities: enumerate, describe,
 * labeled store, accessibility class. The login keychain unlocks with the login
 * session, so [isLocked] is false and [unlock]/[lock] are no-ops; [onWatch] is
 * inert (no SecItem change feed).
 */
internal class KeychainVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val bindings: SecurityBindings,
    namespace: String,
    collection: String?,
    private val accessibilityName: String,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "keychain (SecItem)"),
    EnumerableVault, DescribableVault, LabeledVault, UnlockableVault, WatchableVault, MigratableVault {

    private val service = if (collection != null) "$namespace:$collection" else namespace

    override fun storeRaw(key: String, secret: ByteArray): Boolean =
        bindings.store(service, key, secret, null, accessibilityName)

    override fun retrieveRaw(key: String): ByteArray? = bindings.retrieve(service, key)

    override fun deleteRaw(key: String): Boolean = bindings.delete(service, key)

    override fun containsRaw(key: String): Boolean = bindings.retrieve(service, key) != null

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { bindings.store(service, key, secret, label, accessibilityName) }
    }

    override fun list(): List<String> = bounded(emptyList()) {
        bindings.enumerate(service).filterNot { it == PROBE_KEY }
    }

    override fun clear(): Int = bounded(-1) {
        var removed = 0
        for (account in bindings.enumerate(service)) if (bindings.delete(service, account)) removed++
        removed
    }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null) {
            val meta = bindings.describe(service, key) ?: return@bounded null
            EntryMetadata(
                label = meta.label,
                created = meta.createdSeconds.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) },
                modified = meta.modifiedSeconds.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) },
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
        data class Ready(val bindings: SecurityBindings) : Setup
        data class Unavailable(val availability: VaultAvailability) : Setup
    }

    companion object {
        private val log = LoggerFactory.getLogger(KeychainVault::class.java)
        private const val PROBE_KEY = "__libvault_probe__"
        private val PROBE_VALUE = "ok".toByteArray(StandardCharsets.UTF_8)

        fun create(config: VaultConfig): ProbeResult {
            val accessibilityName = config.accessibility.cfConstantName
            val service = if (config.collection != null) "${config.namespace}:${config.collection}" else config.namespace
            val executor = Executors.newSingleThreadExecutor { r ->
                Thread(r, "libvault-keychain").apply { isDaemon = true }
            }
            val setup = try {
                executor.submit(
                    Callable {
                        val bindings = SecurityBindings.load() ?: return@Callable Setup.Unavailable(VaultAvailability.LibraryUnavailable)
                        val ok = bindings.store(service, PROBE_KEY, PROBE_VALUE, null, accessibilityName) &&
                            bindings.retrieve(service, PROBE_KEY)?.contentEquals(PROBE_VALUE) == true
                        if (ok) {
                            bindings.delete(service, PROBE_KEY)
                            Setup.Ready(bindings)
                        } else {
                            bindings.close()
                            Setup.Unavailable(VaultAvailability.ServiceUnavailable)
                        }
                    },
                ).get(config.probeTimeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                log.info("keychain setup failed: {}", e.message ?: e.javaClass.simpleName)
                executor.shutdownNow()
                return ProbeResult.Unavailable(VaultAvailability.ServiceUnavailable)
            }
            return when (setup) {
                is Setup.Ready ->
                    ProbeResult.Opened(KeychainVault(executor, config.opTimeoutMs, setup.bindings, config.namespace, config.collection, accessibilityName))
                is Setup.Unavailable -> {
                    executor.shutdownNow()
                    ProbeResult.Unavailable(setup.availability)
                }
            }
        }
    }
}
