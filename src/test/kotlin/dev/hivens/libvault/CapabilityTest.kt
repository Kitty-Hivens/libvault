package dev.hivens.libvault

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Capability behaviour (enumerate / describe / label / migrate) and discovery,
 * exercised on the two unit-testable tiers: in-memory and the AES-GCM file.
 */
class CapabilityTest {

    private fun memory(): SecretVault =
        Vault.open(VaultConfig("dev.hivens.test", preferredTiers = listOf(VaultTier.Memory)))

    private fun software(dir: Path): SecretVault = Vault.open(
        VaultConfig("dev.hivens.test", softwareFilePath = dir.resolve("v.bin"), preferredTiers = listOf(VaultTier.SoftwareFile)),
    )

    private fun none(): SecretVault =
        Vault.open(VaultConfig("dev.hivens.test", preferredTiers = listOf(VaultTier.None)))

    // ── Discovery ──────────────────────────────────────────────────────────────

    @Test
    fun `memory and file tiers advertise enumerate, describe, label and migrate -- not unlock or watch`() {
        for (vault in listOf(memory())) {
            vault.asEnumerable() shouldNotBe null
            vault.asDescribable() shouldNotBe null
            vault.asLabeled() shouldNotBe null
            vault.asMigratable() shouldNotBe null
            vault.asUnlockable() shouldBe null
            vault.asWatchable() shouldBe null
            vault.close()
        }
    }

    @Test
    fun `the none tier advertises no capabilities`() {
        none().use { vault ->
            vault.asEnumerable() shouldBe null
            vault.asDescribable() shouldBe null
            vault.asLabeled() shouldBe null
            vault.asMigratable() shouldBe null
            vault.asUnlockable() shouldBe null
            vault.asWatchable() shouldBe null
        }
    }

    // ── Enumeration ────────────────────────────────────────────────────────────

    @Test
    fun `list and clear over the memory tier`() {
        memory().use { checkEnumerate(it) }
    }

    @Test
    fun `list and clear over the file tier`(@TempDir dir: Path) {
        software(dir).use { checkEnumerate(it) }
    }

    private fun checkEnumerate(vault: SecretVault) {
        val e = vault.asEnumerable()!!
        vault.store("a", "1".toByteArray())
        vault.store("b", "2".toByteArray())
        vault.store("c", "3".toByteArray())
        e.list().toSet() shouldBe setOf("a", "b", "c")
        e.clear() shouldBe 3
        e.list() shouldBe emptyList()
        vault.contains("a") shouldBe false
    }

    // ── Labels + metadata ──────────────────────────────────────────────────────

    @Test
    fun `labeled store and describe over the memory tier`() {
        memory().use { checkDescribe(it) }
    }

    @Test
    fun `labeled store and describe over the file tier`(@TempDir dir: Path) {
        software(dir).use { checkDescribe(it) }
    }

    private fun checkDescribe(vault: SecretVault) {
        val labeled = vault.asLabeled()!!
        val describable = vault.asDescribable()!!
        labeled.store("k", "secret".toByteArray(), label = "My Secret", attributes = mapOf("kind" to "token"))

        val meta = describable.describe("k")!!
        meta.label shouldBe "My Secret"
        meta.attributes shouldBe mapOf("kind" to "token")
        meta.created shouldNotBe null
        meta.modified shouldNotBe null
        (meta.modified!! >= meta.created!!) shouldBe true

        describable.describe("absent") shouldBe null
    }

    // ── Migration ──────────────────────────────────────────────────────────────

    @Test
    fun `migrate memory to file copies all and deleteAfter empties the source`(@TempDir dir: Path) {
        val src = memory()
        src.store("a", "1".toByteArray())
        src.store("b", "2".toByteArray())
        val dst = software(dir)

        val report = src.asMigratable()!!.migrateTo(dst, deleteAfter = true)
        report.attempted shouldBe 2
        report.copied shouldBe 2
        report.deleted shouldBe 2
        report.complete shouldBe true

        dst.retrieve("a")!!.decodeToString() shouldBe "1"
        dst.retrieve("b")!!.decodeToString() shouldBe "2"
        src.contains("a") shouldBe false
        src.contains("b") shouldBe false

        src.close()
        dst.close()
    }
}
