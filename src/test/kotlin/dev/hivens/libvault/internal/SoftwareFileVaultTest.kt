package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import dev.hivens.libvault.VaultTier
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class SoftwareFileVaultTest {

    private fun machineBound(path: Path) = SoftwareFileVault.open(path, KeyDerivation.MachineBound)
    private fun passphrase(path: Path, pw: String) = SoftwareFileVault.open(path, KeyDerivation.Passphrase(pw.toCharArray()))

    @Test
    fun `round-trips a secret and reports the tier honestly`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { vault ->
            vault.tier shouldBe VaultTier.SoftwareFile
            vault.secure shouldBe false
            vault.store("token", "s3cr3t".toByteArray()) shouldBe true
            vault.retrieve("token")!!.decodeToString() shouldBe "s3cr3t"
            vault.contains("token") shouldBe true
        }
    }

    @Test
    fun `secrets survive a reopen`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { it.store("k", "v".toByteArray()) }
        machineBound(path).use { it.retrieve("k")!!.decodeToString() shouldBe "v" }
    }

    @Test
    fun `multiple records coexist and delete is independent`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { vault ->
            vault.store("a", "va".toByteArray())
            vault.store("b", "vb".toByteArray())
            vault.delete("a") shouldBe true
            vault.contains("a") shouldBe false
            vault.contains("b") shouldBe true
        }
        machineBound(path).use { vault ->
            vault.retrieve("a") shouldBe null
            vault.retrieve("b")!!.decodeToString() shouldBe "vb"
        }
    }

    @Test
    fun `a flipped ciphertext byte fails authentication for that record only`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { vault ->
            vault.store("a", "va".toByteArray())
            vault.store("b", "vb".toByteArray())
        }
        val bytes = Files.readAllBytes(path)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte() // last byte = tail of b's ciphertext
        Files.write(path, bytes)

        machineBound(path).use { vault ->
            vault.retrieve("a")!!.decodeToString() shouldBe "va" // untouched record still authenticates
            vault.retrieve("b") shouldBe null                    // tamper detected by GCM
        }
    }

    @Test
    fun `a wrong passphrase cannot read prior entries and reinitializes on write`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        passphrase(path, "right").use { it.store("k", "secret".toByteArray()) }

        passphrase(path, "wrong").use { vault ->
            vault.retrieve("k") shouldBe null            // verifier mismatch -> unreadable
            vault.contains("k") shouldBe false
            vault.store("k2", "new".toByteArray()) shouldBe true // reinit under the new key
            vault.retrieve("k2")!!.decodeToString() shouldBe "new"
            vault.retrieve("k") shouldBe null            // old, now-dropped entry stays gone
        }
        passphrase(path, "wrong").use { vault ->
            vault.retrieve("k2")!!.decodeToString() shouldBe "new" // the reinitialized file reads back
        }
    }

    @Test
    fun `the right passphrase reads back across reopen`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        passphrase(path, "correct horse").use { it.store("k", "v".toByteArray()) }
        passphrase(path, "correct horse").use { it.retrieve("k")!!.decodeToString() shouldBe "v" }
    }

    @Test
    fun `a corrupt file is treated as empty and rebuilt on next write`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        Files.write(path, "this is not a vault file".toByteArray())
        machineBound(path).use { vault ->
            vault.retrieve("k") shouldBe null
            vault.store("k", "v".toByteArray()) shouldBe true
            vault.retrieve("k")!!.decodeToString() shouldBe "v"
        }
    }

    @Test
    fun `delete on a missing key is idempotently true`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { vault ->
            vault.delete("never-stored") shouldBe true
        }
    }

    @Test
    fun `binary secrets with embedded nulls survive`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        val blob = ByteArray(256) { it.toByte() } // 0x00..0xFF
        machineBound(path).use { vault ->
            vault.store("blob", blob) shouldBe true
            vault.retrieve("blob")!!.toList() shouldBe blob.toList()
        }
    }

    @Test
    fun `delete under a wrong passphrase cannot rewrite the file`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        passphrase(path, "right").use { it.store("k", "secret".toByteArray()) }
        // Wrong key: can't read, and must not be able to delete/persist either.
        passphrase(path, "wrong").use { vault ->
            vault.delete("k") shouldBe true // reported gone (no-op), file left untouched
        }
        // The rightful holder still sees the entry intact.
        passphrase(path, "right").use { vault ->
            vault.retrieve("k")!!.decodeToString() shouldBe "secret"
        }
    }

    @Test
    fun `operations after close are inert and do not corrupt the file`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        val vault = passphrase(path, "pw")
        vault.store("k", "v".toByteArray()) shouldBe true
        vault.close()
        vault.store("k2", "new".toByteArray()) shouldBe false // no silent reinit with a blanked passphrase
        vault.retrieve("k") shouldBe null
        vault.contains("k") shouldBe false
        // Reopen with the real key: original entry intact, the post-close write never landed.
        passphrase(path, "pw").use { v ->
            v.retrieve("k")!!.decodeToString() shouldBe "v"
            v.retrieve("k2") shouldBe null
        }
    }
}
