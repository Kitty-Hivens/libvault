package dev.hivens.libvault.linux

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.Vault
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.asEnumerable
import dev.hivens.libvault.asUnlockable
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder

/**
 * The Secret Service backend against a real service. It runs only where
 * LIBVAULT_SECRET_SERVICE=1 says a disposable one is on the session bus, as in
 * CI, because it locks the default collection: on a desktop that would be the
 * user's login keyring. Where the variable is set, a service that cannot be
 * reached is a failure, not a skip.
 *
 * Locking runs last: unlocking again takes a prompt, which a headless service
 * cannot show, so the collection stays locked for whatever would follow.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
class SecretServiceTest {

    private lateinit var vault: SecretVault

    @BeforeEach
    fun open() {
        assumeTrue(System.getenv("LIBVAULT_SECRET_SERVICE") == "1", "LIBVAULT_SECRET_SERVICE=1 not set")
        vault = Vault.open(
            VaultConfig(
                "dev.hivens.libvault.test.${System.nanoTime()}",
                preferredTiers = listOf(VaultTier.OsKeyring),
                probeTimeoutMs = 10_000,
                opTimeoutMs = 10_000,
            ),
        )
        vault.tier shouldBe VaultTier.OsKeyring
    }

    @AfterEach
    fun close() {
        if (!::vault.isInitialized) return
        // Each test has a namespace of its own. A locked collection keeps what
        // it holds, the service is thrown away after the run.
        vault.asEnumerable()?.clear()
        vault.close()
    }

    @Test
    @Order(1)
    fun `round-trips a secret`() {
        vault.store("k", "v".toByteArray()) shouldBe true
        vault.retrieve("k")!!.decodeToString() shouldBe "v"
        vault.delete("k") shouldBe true
        vault.retrieve("k") shouldBe null
    }

    @Test
    @Order(2)
    fun `a collection locked after open is noticed by every operation`() {
        vault.store("before", "1".toByteArray()) shouldBe true
        vault.asUnlockable()!!.lock() shouldBe true

        vault.asUnlockable()!!.isLocked() shouldBe true
        vault.store("after", "2".toByteArray()) shouldBe false
        vault.retrieve("before") shouldBe null
        vault.contains("before") shouldBe false
        vault.delete("before") shouldBe false
        vault.asEnumerable()!!.clear() shouldBe -1
    }
}
