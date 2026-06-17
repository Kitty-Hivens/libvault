package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultTier
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Base for the OS-keyring backends. Two jobs:
 *
 *  1. **Thread affinity.** libdbus connections (and, defensively, the Win32 /
 *     Keychain handles) are used from exactly one owned thread. Every raw op
 *     and the native setup run on [executor]'s single thread.
 *
 *  2. **Never hang.** Each public op submits its raw counterpart to [executor]
 *     and waits at most [opTimeoutMs]. A locked, prompt-only, or wedged keyring
 *     service makes the op overrun its budget and degrade to false/null instead
 *     of freezing the caller -- the whole reason this storage lives behind a
 *     library boundary.
 *
 * Subclasses implement the synchronous `*Raw` ops; they may block freely, the
 * timeout is enforced here.
 */
internal abstract class SingleThreadVault(
    private val executor: ExecutorService,
    private val opTimeoutMs: Long,
    final override val tier: VaultTier,
    final override val backend: String,
) : SecretVault {

    protected val log: Logger = LoggerFactory.getLogger(javaClass)
    private val closed = AtomicBoolean(false)

    protected abstract fun storeRaw(key: String, secret: ByteArray): Boolean
    protected abstract fun retrieveRaw(key: String): ByteArray?
    protected abstract fun deleteRaw(key: String): Boolean
    protected abstract fun containsRaw(key: String): Boolean

    /** Release native resources. Runs on [executor]'s thread during [close]. */
    protected open fun cleanupRaw() {}

    final override fun store(key: String, secret: ByteArray): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { storeRaw(key, secret) }
    }

    final override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null) { retrieveRaw(key) }
    }

    final override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { deleteRaw(key) }
    }

    final override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false) { containsRaw(key) }
    }

    /**
     * Run [op] on the dispatch thread, bounded by [opTimeoutMs]; on timeout or
     * failure return [default]. Subclasses wrap their capability ops (list,
     * describe, labeled store, ...) through this so those degrade and stay
     * connection-thread-safe like the core ops.
     */
    protected fun <T> bounded(default: T, op: () -> T): T {
        if (closed.get()) return default
        return try {
            executor.submit(Callable { op() }).get(opTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            log.warn("{} op exceeded {} ms -- degrading to fallback value", backend, opTimeoutMs)
            default
        } catch (e: Exception) {
            log.warn("{} op failed: {}", backend, e.message ?: e.javaClass.simpleName)
            default
        }
    }

    final override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { executor.submit(Callable { cleanupRaw() }).get(opTimeoutMs, TimeUnit.MILLISECONDS) }
            .onFailure { log.warn("{} cleanup did not finish cleanly: {}", backend, it.message) }
        executor.shutdownNow()
    }
}
