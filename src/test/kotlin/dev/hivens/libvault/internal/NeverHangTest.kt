package dev.hivens.libvault.internal

import dev.hivens.libvault.VaultTier
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.system.measureTimeMillis

/**
 * The whole reason this storage lives behind a library boundary: a wedged
 * backend must degrade within the timeout budget, never block the caller.
 */
class NeverHangTest {

    /** A backend whose every native op blocks effectively forever. */
    private class WedgedVault(executor: ExecutorService, opTimeoutMs: Long) :
        SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "wedged-test") {
        override fun storeRaw(key: String, secret: ByteArray): Boolean { Thread.sleep(60_000); return true }
        override fun retrieveRaw(key: String): ByteArray? { Thread.sleep(60_000); return ByteArray(0) }
        override fun deleteRaw(key: String): Boolean { Thread.sleep(60_000); return true }
        override fun containsRaw(key: String): Boolean { Thread.sleep(60_000); return true }
    }

    private fun executor() = Executors.newSingleThreadExecutor { r -> Thread(r).apply { isDaemon = true } }

    @Test
    fun `a wedged op degrades to the fallback value within the op timeout`() {
        val vault = WedgedVault(executor(), opTimeoutMs = 150)
        val elapsed = measureTimeMillis {
            vault.store("k", byteArrayOf(1)) shouldBe false
            vault.retrieve("k") shouldBe null
            vault.contains("k") shouldBe false
        }
        // Three 60s sleeps would be 180s; we must be back in well under that.
        (elapsed < 5_000L) shouldBe true
        vault.close()
    }
}
