package dev.hivens.libvault

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Tier-selection logic, kept independent of whether THIS host has an OS keyring
 * (the developer's machine does; CI doesn't) by never listing OsKeyring as the
 * only option -- every config here resolves the same way everywhere.
 */
class VaultSelectionTest {

    private fun config(dir: Path, vararg tiers: VaultTier, allowSoftware: Boolean = true) = VaultConfig(
        namespace = "dev.hivens.libvault.test",
        softwareFilePath = dir.resolve("vault.bin"),
        allowSoftwareFallback = allowSoftware,
        preferredTiers = tiers.toList(),
    )

    @Test
    fun `memory tier is selected when listed first`(@TempDir dir: Path) {
        Vault.open(config(dir, VaultTier.Memory)).use { it.tier shouldBe VaultTier.Memory }
    }

    @Test
    fun `none tier is selected when listed`(@TempDir dir: Path) {
        Vault.open(config(dir, VaultTier.None)).use { vault ->
            vault.tier shouldBe VaultTier.None
            vault.store("k", byteArrayOf(1)) shouldBe false // disabled -> nothing persists
            vault.retrieve("k") shouldBe null
        }
    }

    @Test
    fun `software file tier is selected and actually works`(@TempDir dir: Path) {
        Vault.open(config(dir, VaultTier.SoftwareFile)).use { vault ->
            vault.tier shouldBe VaultTier.SoftwareFile
            vault.store("k", "v".toByteArray()) shouldBe true
            vault.retrieve("k")!!.decodeToString() shouldBe "v"
        }
    }

    @Test
    fun `first listed tier wins`(@TempDir dir: Path) {
        Vault.open(config(dir, VaultTier.Memory, VaultTier.SoftwareFile)).use { it.tier shouldBe VaultTier.Memory }
    }

    @Test
    fun `software tier is skipped when the fallback is disabled, flooring to none`(@TempDir dir: Path) {
        Vault.open(config(dir, VaultTier.SoftwareFile, allowSoftware = false)).use { it.tier shouldBe VaultTier.None }
    }

    @Test
    fun `an empty preference list floors to the software file when allowed`(@TempDir dir: Path) {
        Vault.open(config(dir, allowSoftware = true)).use { it.tier shouldBe VaultTier.SoftwareFile }
    }

    @Test
    fun `an empty preference list floors to none when software is disallowed`(@TempDir dir: Path) {
        Vault.open(config(dir, allowSoftware = false)).use { it.tier shouldBe VaultTier.None }
    }
}
