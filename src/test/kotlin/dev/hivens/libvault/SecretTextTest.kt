package dev.hivens.libvault

import dev.hivens.libvault.internal.MemoryVault
import dev.hivens.libvault.internal.SecretText
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

class SecretTextTest {

    @Test
    fun `utf8 transcode round-trips ascii, cyrillic and emoji`() {
        for (s in listOf("hunter2", "пароль-2024", "p@ss🔐word", "")) {
            val bytes = SecretText.toUtf8(s.toCharArray())
            bytes.decodeToString() shouldBe s
            String(SecretText.fromUtf8(bytes)) shouldBe s
        }
    }

    @Test
    fun `storeString and retrieveString round-trip through a vault without an interned String`() {
        val vault = MemoryVault()
        vault.storeString("pw", "пароль🔐".toCharArray()) shouldBe true
        String(vault.retrieveString("pw")!!) shouldBe "пароль🔐"
    }

    @Test
    fun `retrieveString returns null for an absent key`() {
        MemoryVault().retrieveString("nope") shouldBe null
    }

    @Test
    fun `storeString zeroes its internal utf8 copy but leaves the caller array intact`() {
        val vault = MemoryVault()
        val secret = "keepme".toCharArray()
        vault.storeString("k", secret)
        // The contract zeroes the internal byte copy, not the caller's chars.
        String(secret) shouldBe "keepme"
        String(vault.retrieveString("k")!!) shouldBe "keepme"
    }
}
