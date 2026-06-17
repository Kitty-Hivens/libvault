package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.junit.jupiter.api.Test

class KdfEngineTest {

    private val salt = ByteArray(16) { it.toByte() }
    private val otherSalt = ByteArray(16) { (it + 1).toByte() }

    @Test
    fun `machine-bound derivation is deterministic for a fixed salt and 32 bytes long`() {
        val a = KdfEngine.deriveMachineBound(salt)
        val b = KdfEngine.deriveMachineBound(salt)
        a.size shouldBe KdfEngine.KEY_LEN_BYTES
        a.toList() shouldBe b.toList()
    }

    @Test
    fun `machine-bound derivation changes with the salt`() {
        KdfEngine.deriveMachineBound(salt).toList() shouldNotBe KdfEngine.deriveMachineBound(otherSalt).toList()
    }

    @Test
    fun `argon2 passphrase derivation is deterministic and salt-sensitive`() {
        val a = KdfEngine.derivePassphrase("pw".toCharArray(), salt)
        val b = KdfEngine.derivePassphrase("pw".toCharArray(), salt)
        a.size shouldBe KdfEngine.KEY_LEN_BYTES
        a.toList() shouldBe b.toList()
        KdfEngine.derivePassphrase("pw".toCharArray(), otherSalt).toList() shouldNotBe a.toList()
    }

    @Test
    fun `different passphrases derive different keys`() {
        KdfEngine.derivePassphrase("alpha".toCharArray(), salt).toList() shouldNotBe
            KdfEngine.derivePassphrase("beta".toCharArray(), salt).toList()
    }

    @Test
    fun `kdfId distinguishes the two derivations`() {
        KdfEngine.kdfId(KeyDerivation.MachineBound) shouldBe KdfEngine.KDF_MACHINE_BOUND
        KdfEngine.kdfId(KeyDerivation.Passphrase("x".toCharArray())) shouldBe KdfEngine.KDF_PASSPHRASE
    }
}
