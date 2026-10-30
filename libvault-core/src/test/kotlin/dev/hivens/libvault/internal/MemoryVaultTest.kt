package dev.hivens.libvault.internal

import dev.hivens.libvault.VaultTier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

class MemoryVaultTest {

    @Test
    fun `store then retrieve round-trips`() {
        val vault = MemoryVault()
        vault.store("k", byteArrayOf(1, 2, 3)) shouldBe true
        vault.retrieve("k")!!.toList() shouldBe listOf<Byte>(1, 2, 3)
        vault.contains("k") shouldBe true
        vault.tier shouldBe VaultTier.Memory
        vault.secure shouldBe false
    }

    @Test
    fun `store overwrites`() {
        val vault = MemoryVault()
        vault.store("k", byteArrayOf(1))
        vault.store("k", byteArrayOf(9, 9))
        vault.retrieve("k")!!.toList() shouldBe listOf<Byte>(9, 9)
    }

    @Test
    fun `delete is idempotent`() {
        val vault = MemoryVault()
        vault.store("k", byteArrayOf(1))
        vault.delete("k") shouldBe true
        vault.delete("k") shouldBe true
        vault.contains("k") shouldBe false
        vault.retrieve("k") shouldBe null
    }

    @Test
    fun `retrieve returns a copy -- caller mutation can't reach the store`() {
        val vault = MemoryVault()
        vault.store("k", byteArrayOf(1, 2, 3))
        vault.retrieve("k")!![0] = 99
        vault.retrieve("k")!!.toList() shouldBe listOf<Byte>(1, 2, 3)
    }

    @Test
    fun `blank key is rejected`() {
        val vault = MemoryVault()
        shouldThrow<IllegalArgumentException> { vault.store("", byteArrayOf(1)) }
        shouldThrow<IllegalArgumentException> { vault.retrieve("") }
    }

    @Test
    fun `close clears everything`() {
        val vault = MemoryVault()
        vault.store("k", byteArrayOf(1))
        vault.close()
        vault.contains("k") shouldBe false
    }
}
