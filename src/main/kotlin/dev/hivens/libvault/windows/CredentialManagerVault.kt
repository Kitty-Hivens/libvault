package dev.hivens.libvault.windows

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.internal.SingleThreadVault
import dev.hivens.libvault.internal.openOnDispatchThread
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService

/**
 * [VaultTier.OsKeyring] on Windows -- Credential Manager via [Win32Bindings].
 * Raw bytes go in and out (no UTF-16 round-trip), so any binary secret survives.
 */
internal class CredentialManagerVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val bindings: Win32Bindings,
    private val namespace: String,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "credential-manager (DPAPI)") {

    private fun target(key: String): String = "$namespace/$key"

    override fun storeRaw(key: String, secret: ByteArray): Boolean = bindings.write(target(key), secret)

    override fun retrieveRaw(key: String): ByteArray? = bindings.read(target(key))

    override fun deleteRaw(key: String): Boolean =
        if (bindings.delete(target(key))) true else bindings.read(target(key)) == null

    override fun containsRaw(key: String): Boolean = bindings.read(target(key)) != null

    override fun cleanupRaw() {
        bindings.close()
    }

    companion object {
        private val log = LoggerFactory.getLogger(CredentialManagerVault::class.java)
        private const val PROBE_KEY = "__libvault_probe__"
        private val PROBE_VALUE = "ok".toByteArray(StandardCharsets.UTF_8)

        fun create(config: VaultConfig): SecretVault? {
            val opened = openOnDispatchThread(log, "libvault-credman", config.probeTimeoutMs) {
                val bindings = Win32Bindings.load() ?: return@openOnDispatchThread null
                // A write+read+delete round-trip is the only signal that
                // distinguishes "service answers" from "symbols loaded but the
                // store is unusable" -- mirror the libsecret/Keychain probes.
                val probe = "${config.namespace}/$PROBE_KEY"
                val ok = bindings.write(probe, PROBE_VALUE) &&
                    bindings.read(probe)?.contentEquals(PROBE_VALUE) == true
                if (ok) {
                    bindings.delete(probe)
                    bindings
                } else {
                    bindings.close()
                    null
                }
            } ?: return null
            val (executor, bindings) = opened
            return CredentialManagerVault(executor, config.opTimeoutMs, bindings, config.namespace)
        }
    }
}
