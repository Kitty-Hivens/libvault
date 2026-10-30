package dev.hivens.libvault.internal

import dev.hivens.libvault.KeyDerivation
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Derives the 256-bit AES key for the software-file tier. Two strategies, one
 * per [KeyDerivation] variant; the chosen one is recorded as a [kdfId] byte in
 * the file header so a reader knows how to re-derive (and detect a mismatch).
 *
 * MachineBound uses PBKDF2-HMAC-SHA256 -- ships in the JDK, no dependency, and
 * the low-entropy machine seed doesn't benefit from a memory-hard KDF anyway
 * (an attacker with the seed skips the KDF). Passphrase uses Argon2id, where the
 * memory-hardness genuinely raises the cost of brute-forcing a human passphrase.
 */
internal object KdfEngine {

    const val KDF_MACHINE_BOUND: Int = FileKey.MACHINE_BOUND
    const val KDF_PASSPHRASE: Int = FileKey.PASSPHRASE

    const val KEY_LEN_BYTES: Int = 32
    private const val KEY_LEN_BITS: Int = KEY_LEN_BYTES * 8

    // PBKDF2 work factor. One-time per process (the key is cached), so a high
    // count is free at runtime; OWASP's 2023 floor for PBKDF2-HMAC-SHA256.
    private const val PBKDF2_ITERATIONS: Int = 600_000

    // Argon2id parameters: 64 MiB, 3 passes, single lane. A balance that stays
    // sub-100ms on a desktop while costing a GPU attacker real memory bandwidth.
    private const val ARGON2_ITERATIONS: Int = 3
    private const val ARGON2_MEMORY_KB: Int = 64 * 1024
    private const val ARGON2_PARALLELISM: Int = 1

    /** The header byte identifying which derivation produced a file. */
    fun kdfId(kd: KeyDerivation): Int = when (kd) {
        is KeyDerivation.MachineBound -> KDF_MACHINE_BOUND
        is KeyDerivation.Passphrase -> KDF_PASSPHRASE
    }

    fun deriveMachineBound(salt: ByteArray): ByteArray {
        val seed = MachineId.seed().toCharArray()
        // PBEKeySpec keeps its own copy of the password until told otherwise.
        val spec = PBEKeySpec(seed, salt, PBKDF2_ITERATIONS, KEY_LEN_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            seed.fill('\u0000')
        }
    }

    fun derivePassphrase(passphrase: CharArray, salt: ByteArray): ByteArray {
        val pwBytes = SecretText.toUtf8(passphrase)
        return try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ARGON2_ITERATIONS)
                .withMemoryAsKB(ARGON2_MEMORY_KB)
                .withParallelism(ARGON2_PARALLELISM)
                .withSalt(salt)
                .build()
            val generator = Argon2BytesGenerator().apply { init(params) }
            ByteArray(KEY_LEN_BYTES).also { generator.generateBytes(pwBytes, it) }
        } finally {
            pwBytes.fill(0)
        }
    }
}
