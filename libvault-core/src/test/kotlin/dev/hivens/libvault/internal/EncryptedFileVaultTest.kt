package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import dev.hivens.libvault.VaultTier
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name

class EncryptedFileVaultTest {

    private fun machineBound(path: Path) = EncryptedFileVault.openSoftware(path, KeyDerivation.MachineBound, LOCK_TIMEOUT_MS)
    private fun passphrase(path: Path, pw: String) =
        EncryptedFileVault.openSoftware(path, KeyDerivation.Passphrase(pw.toCharArray()), LOCK_TIMEOUT_MS)

    private fun asideFiles(dir: Path): List<Path> = dir.listDirectoryEntries().filter { it.name.startsWith("vault.bin.unreadable-") }

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
    fun `a flipped verifier byte makes the vault unreadable`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { vault ->
            vault.store("a", "va".toByteArray())
            vault.store("b", "vb".toByteArray())
        }
        // Offset 40 begins the verifier ciphertext (magic4+ver1+kdf1+saltLen1+
        // salt16+nonceLen1+nonce12+ctLen4). Corrupting it fails the verifier GCM,
        // so the key no longer "matches" and nothing is readable.
        val bytes = Files.readAllBytes(path)
        bytes[44] = (bytes[44] + 1).toByte()
        Files.write(path, bytes)

        machineBound(path).use { vault ->
            vault.retrieve("a") shouldBe null
            vault.retrieve("b") shouldBe null
        }
    }

    @Test
    fun `a wrong passphrase cannot read prior entries and moves the file aside on write`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        passphrase(path, "right").use { it.store("k", "secret".toByteArray()) }

        passphrase(path, "wrong").use { vault ->
            vault.retrieve("k") shouldBe null            // verifier mismatch -> unreadable
            vault.contains("k") shouldBe false
            vault.store("k2", "new".toByteArray()) shouldBe true // a new file under the new key
            vault.retrieve("k2")!!.decodeToString() shouldBe "new"
            vault.retrieve("k") shouldBe null
        }
        passphrase(path, "wrong").use { vault ->
            vault.retrieve("k2")!!.decodeToString() shouldBe "new"
        }

        // The old file was kept, and the right passphrase still opens it.
        val aside = asideFiles(dir)
        aside shouldHaveSize 1
        passphrase(aside.single(), "right").use { vault ->
            vault.retrieve("k")!!.decodeToString() shouldBe "secret"
        }
    }

    @Test
    fun `the right passphrase reads back across reopen`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        passphrase(path, "correct horse").use { it.store("k", "v".toByteArray()) }
        passphrase(path, "correct horse").use { it.retrieve("k")!!.decodeToString() shouldBe "v" }
    }

    @Test
    fun `a corrupt file is kept aside and a new one is started on the next write`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        val junk = "this is not a vault file".toByteArray()
        Files.write(path, junk)
        machineBound(path).use { vault ->
            vault.retrieve("k") shouldBe null
            vault.store("k", "v".toByteArray()) shouldBe true
            vault.retrieve("k")!!.decodeToString() shouldBe "v"
        }
        Files.readAllBytes(asideFiles(dir).single()).toList() shouldBe junk.toList()
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
            vault.clear() shouldBe 0
        }
        // The rightful holder still sees the entry intact, in place.
        passphrase(path, "right").use { vault ->
            vault.retrieve("k")!!.decodeToString() shouldBe "secret"
        }
        asideFiles(dir) shouldBe emptyList()
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

    // ── Sharing one file ──────────────────────────────────────────────────────

    @Test
    fun `two vaults on one file see each other's writes and deletes`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { a ->
            machineBound(path).use { b ->
                a.store("from-a", "1".toByteArray()) shouldBe true
                b.store("from-b", "2".toByteArray()) shouldBe true
                a.retrieve("from-b")!!.decodeToString() shouldBe "2"
                b.retrieve("from-a")!!.decodeToString() shouldBe "1"
                a.list().shouldContainExactlyInAnyOrder("from-a", "from-b")

                b.delete("from-a") shouldBe true
                a.contains("from-a") shouldBe false
            }
        }
    }

    @Test
    fun `a file deleted underneath an open vault reads as empty`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { vault ->
            vault.store("k", "v".toByteArray()) shouldBe true
            Files.delete(path)
            vault.retrieve("k") shouldBe null
            vault.list() shouldBe emptyList()
            vault.store("k2", "v2".toByteArray()) shouldBe true
            vault.list() shouldBe listOf("k2")
        }
    }

    @Test
    fun `concurrent writers through two vaults lose no record`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        val perWriter = 25
        val a = machineBound(path)
        val b = machineBound(path)
        val start = CountDownLatch(1)
        val writers = listOf("a" to a, "b" to b).map { (name, vault) ->
            thread {
                start.await()
                repeat(perWriter) { vault.store("$name-$it", "$it".toByteArray()) shouldBe true }
            }
        }
        start.countDown()
        writers.forEach { it.join(TimeUnit.SECONDS.toMillis(60)) }
        a.close()
        b.close()

        machineBound(path).use { vault -> vault.list() shouldHaveSize perWriter * 2 }
    }

    @Test
    fun `writers in separate processes lose no record`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        val perWriter = 20
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val classpath = System.getProperty("java.class.path")
        val children = listOf("p1", "p2").map { prefix ->
            ProcessBuilder(java, "-cp", classpath, WRITER_MAIN, path.toString(), prefix, perWriter.toString())
                .redirectErrorStream(true)
                .start()
        }
        // This process writes at the same time, through its own vault.
        machineBound(path).use { vault ->
            repeat(perWriter) { vault.store("self-$it", "$it".toByteArray()) shouldBe true }
        }
        for (child in children) {
            child.waitFor(120, TimeUnit.SECONDS) shouldBe true
            val output = child.inputStream.bufferedReader().readText()
            check(child.exitValue() == 0) { "writer process failed:\n$output" }
        }

        machineBound(path).use { vault ->
            val keys = vault.list()
            keys shouldHaveSize perWriter * 3
            vault.retrieve("p1-0")!!.decodeToString() shouldBe "0"
            vault.retrieve("p2-${perWriter - 1}")!!.decodeToString() shouldBe "${perWriter - 1}"
        }
    }

    @Test
    fun `two vaults reaching one file by different paths lose no record`(@TempDir dir: Path) {
        val real = Files.createDirectory(dir.resolve("real"))
        val link = try {
            Files.createSymbolicLink(dir.resolve("link"), real)
        } catch (e: Exception) {
            assumeTrue(false, "symbolic links unavailable: ${e.message}")
            return
        }
        val perWriter = 25
        val a = machineBound(real.resolve("vault.bin"))
        val b = machineBound(link.resolve("vault.bin"))
        val failures = AtomicInteger()
        val start = CountDownLatch(1)
        val writers = listOf("a" to a, "b" to b).map { (name, vault) ->
            thread {
                start.await()
                repeat(perWriter) { if (!vault.store("$name-$it", "$it".toByteArray())) failures.incrementAndGet() }
            }
        }
        start.countDown()
        writers.forEach { it.join(TimeUnit.SECONDS.toMillis(60)) }
        a.close()
        b.close()

        failures.get() shouldBe 0
        machineBound(real.resolve("vault.bin")).use { vault -> vault.list() shouldHaveSize perWriter * 2 }
    }

    // ── Failures that say nothing about the file ──────────────────────────────

    /** The machine-bound key, until [failing] is set: then every lookup throws, as a Keystore that did not answer. */
    private class FlakyKey : FileKey {
        private val real = DerivedFileKey(KeyDerivation.MachineBound)

        @Volatile var failing = false

        override val kdfId: Int = real.kdfId
        override val saltLength: Int = real.saltLength

        override fun keyFor(salt: ByteArray): SecretKey? {
            if (failing) throw IllegalStateException("key source unavailable")
            return real.keyFor(salt)
        }

        override fun newKey(salt: ByteArray): SecretKey {
            if (failing) throw IllegalStateException("key source unavailable")
            return real.newKey(salt)
        }

        override fun close() = real.close()
    }

    @Test
    fun `a key source that fails neither empties nor moves the file`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { it.store("a", "1".toByteArray()) shouldBe true }

        // Failing from the first load: the state the vault would otherwise
        // settle into after it is the one that looks like "no file yet".
        val flaky = FlakyKey().apply { failing = true }
        EncryptedFileVault.open(path, flaky, LOCK_TIMEOUT_MS, VaultTier.OsKeyring, "flaky").use { vault ->
            vault.retrieve("a") shouldBe null
            vault.store("b", "2".toByteArray()) shouldBe false
            vault.delete("a") shouldBe false

            flaky.failing = false
            vault.retrieve("a")!!.decodeToString() shouldBe "1"
            vault.store("b", "2".toByteArray()) shouldBe true
        }
        asideFiles(dir) shouldBe emptyList()
        machineBound(path).use { it.list().shouldContainExactlyInAnyOrder("a", "b") }
    }

    @Test
    fun `a key the cipher refuses is a failure, not a wrong key`(@TempDir dir: Path) {
        val path = dir.resolve("vault.bin")
        machineBound(path).use { it.store("a", "1".toByteArray()) shouldBe true }

        // An HMAC key is no AES key: Cipher.init throws InvalidKeyException,
        // which is the key source misbehaving, not the file's tag failing.
        val unusable = object : FileKey {
            override val kdfId: Int = FileKey.MACHINE_BOUND
            override val saltLength: Int = 16
            private val key = SecretKeySpec(ByteArray(32), "HmacSHA256")
            override fun keyFor(salt: ByteArray): SecretKey = key
            override fun newKey(salt: ByteArray): SecretKey = key
            override fun close() {}
        }
        EncryptedFileVault.open(path, unusable, LOCK_TIMEOUT_MS, VaultTier.SoftwareFile, "unusable").use { vault ->
            vault.store("b", "2".toByteArray()) shouldBe false
        }
        asideFiles(dir) shouldBe emptyList()
        machineBound(path).use { it.retrieve("a")!!.decodeToString() shouldBe "1" }
    }

    @Test
    fun `a file this process cannot read is not moved aside`(@TempDir dir: Path) {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"), "POSIX permissions only")
        val path = dir.resolve("vault.bin")
        machineBound(path).use { it.store("a", "1".toByteArray()) shouldBe true }
        val permissions = Files.getPosixFilePermissions(path)
        Files.setPosixFilePermissions(path, emptySet())
        try {
            assumeTrue(!Files.isReadable(path), "running with permission to read anything")
            machineBound(path).use { vault ->
                vault.retrieve("a") shouldBe null
                vault.store("b", "2".toByteArray()) shouldBe false
            }
        } finally {
            Files.setPosixFilePermissions(path, permissions)
        }
        asideFiles(dir) shouldBe emptyList()
        machineBound(path).use { it.retrieve("a")!!.decodeToString() shouldBe "1" }
    }

    private companion object {
        const val LOCK_TIMEOUT_MS = 10_000L
        const val WRITER_MAIN = "dev.hivens.libvault.internal.EncryptedFileWriterMainKt"
    }
}
