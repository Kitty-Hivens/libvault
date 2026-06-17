package dev.hivens.libvault

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

/**
 * [Vault.probe] over the tiers that don't depend on a live OS keyring. The
 * OsKeyring availability classification is environment-specific and is covered
 * by the smoke harness, not here.
 */
class VaultProbeTest {

    @Test
    fun `probe reports each preferred non-keyring tier as available`() {
        val statuses = Vault.probe(
            VaultConfig(
                "dev.hivens.test",
                preferredTiers = listOf(VaultTier.Memory, VaultTier.None, VaultTier.SoftwareFile),
            ),
        )
        statuses.map { it.tier } shouldBe listOf(VaultTier.Memory, VaultTier.None, VaultTier.SoftwareFile)
        statuses.forEach {
            it.availability shouldBe VaultAvailability.Available
            it.usable shouldBe true
        }
    }

    @Test
    fun `probe of an empty preference list is empty`() {
        Vault.probe(VaultConfig("dev.hivens.test", preferredTiers = emptyList())) shouldBe emptyList()
    }

    @Test
    fun `software tier reports not-secure, memory not-secure`() {
        val statuses = Vault.probe(
            VaultConfig("dev.hivens.test", preferredTiers = listOf(VaultTier.SoftwareFile, VaultTier.Memory)),
        )
        statuses.forEach { it.secure shouldBe false }
    }
}
