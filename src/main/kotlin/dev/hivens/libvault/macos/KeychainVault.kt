package dev.hivens.libvault.macos

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.internal.SingleThreadVault
import dev.hivens.libvault.internal.openOnDispatchThread
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService

/**
 * [VaultTier.OsKeyring] on macOS -- Keychain Services via [SecurityBindings].
 * `service` is the [VaultConfig.namespace]; `account` is the key.
 */
internal class KeychainVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val bindings: SecurityBindings,
    private val namespace: String,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "keychain (SecItem)") {

    override fun storeRaw(key: String, secret: ByteArray): Boolean = bindings.store(namespace, key, secret)

    override fun retrieveRaw(key: String): ByteArray? = bindings.retrieve(namespace, key)

    override fun deleteRaw(key: String): Boolean = bindings.delete(namespace, key)

    override fun containsRaw(key: String): Boolean = bindings.retrieve(namespace, key) != null

    override fun cleanupRaw() {
        bindings.close()
    }

    companion object {
        private val log = LoggerFactory.getLogger(KeychainVault::class.java)
        private const val PROBE_KEY = "__libvault_probe__"
        private val PROBE_VALUE = "ok".toByteArray(StandardCharsets.UTF_8)

        fun create(config: VaultConfig): SecretVault? {
            val opened = openOnDispatchThread(log, "libvault-keychain", config.probeTimeoutMs) {
                val bindings = SecurityBindings.load() ?: return@openOnDispatchThread null
                val ok = bindings.store(config.namespace, PROBE_KEY, PROBE_VALUE) &&
                    bindings.retrieve(config.namespace, PROBE_KEY)?.contentEquals(PROBE_VALUE) == true
                if (ok) {
                    bindings.delete(config.namespace, PROBE_KEY)
                    bindings
                } else {
                    bindings.close()
                    null
                }
            } ?: return null
            val (executor, bindings) = opened
            return KeychainVault(executor, config.opTimeoutMs, bindings, config.namespace)
        }
    }
}
