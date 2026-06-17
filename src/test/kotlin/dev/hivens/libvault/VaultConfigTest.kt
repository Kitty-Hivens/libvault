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
