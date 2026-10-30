package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import java.nio.file.Path
import kotlin.system.exitProcess

/**
 * The second process in EncryptedFileVaultTest: stores `<prefix>-0` up to
 * `<prefix>-<count - 1>` into the vault file named by the first argument and
 * exits non-zero if any store was refused.
 */
fun main(args: Array<String>) {
    val (path, prefix, count) = args
    val failed = EncryptedFileVault.openSoftware(Path.of(path), KeyDerivation.MachineBound, 10_000).use { vault ->
        (0 until count.toInt()).count { !vault.store("$prefix-$it", "$it".toByteArray()) }
    }
    if (failed > 0) {
        System.err.println("$failed stores refused")
        exitProcess(1)
    }
}
