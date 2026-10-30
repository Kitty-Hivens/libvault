package dev.hivens.libvault

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

class VaultConfigTest {

    @Test
    fun `blank namespace is rejected at construction`() {
        shouldThrow<IllegalArgumentException> { VaultConfig(namespace = "") }
        shouldThrow<IllegalArgumentException> { VaultConfig(namespace = "   ") }
    }

    @Test
    fun `non-positive timeouts are rejected`() {
        shouldThrow<IllegalArgumentException> { VaultConfig(namespace = "ns", probeTimeoutMs = 0) }
        shouldThrow<IllegalArgumentException> { VaultConfig(namespace = "ns", opTimeoutMs = -1) }
        shouldThrow<IllegalArgumentException> { VaultConfig(namespace = "ns", unlockTimeoutMs = 0) }
    }

    @Test
    fun `a blank collection is rejected, null is fine`() {
        shouldThrow<IllegalArgumentException> { VaultConfig(namespace = "ns", collection = "  ") }
        VaultConfig(namespace = "ns", collection = null).collection shouldBe null
        VaultConfig(namespace = "ns", collection = "work").collection shouldBe "work"
    }

    @Test
    fun `v0_2 fields default to the conservative case`() {
        val config = VaultConfig(namespace = "ns")
        config.unlockTimeoutMs shouldBe 30_000
        config.accessibility shouldBe Accessibility.WhenUnlocked
        config.collection shouldBe null
        config.unlockPolicy shouldBe UnlockPolicy.Never
    }

    @Test
    fun `defaults are the common case -- keyring then software file`() {
        val config = VaultConfig(namespace = "dev.hivens.nexira")
        config.allowSoftwareFallback shouldBe true
        config.preferredTiers shouldBe listOf(VaultTier.OsKeyring, VaultTier.SoftwareFile)
        config.keyDerivation shouldBe KeyDerivation.MachineBound
    }

    @Test
    fun `tier osBacked flags reflect real protection`() {
        VaultTier.OsKeyring.osBacked shouldBe true
        VaultTier.SoftwareFile.osBacked shouldBe false
        VaultTier.Memory.osBacked shouldBe false
        VaultTier.None.osBacked shouldBe false
    }
}
