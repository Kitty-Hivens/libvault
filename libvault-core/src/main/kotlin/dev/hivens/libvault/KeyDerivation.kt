package dev.hivens.libvault

/**
 * How the [VaultTier.SoftwareFile] fallback derives its AES key. Irrelevant to
 * the OS-keyring tiers -- the OS owns their keys.
 *
 * This is a sealed hierarchy so a future hardware-backed derivation (TPM /
 * Secure Enclave) can be added without breaking the `when` at call sites.
 */
public sealed interface KeyDerivation {

    /**
     * Derive the key from machine-local material (machine-id / hostname / user)
     * via PBKDF2. Zero friction -- no input needed -- but the same material is
     * readable by anything running as this user, so the result is obfuscation,
     * not protection. [SecretVault.secure] stays false.
     */
    public data object MachineBound : KeyDerivation

    /**
     * Derive the key from a caller-supplied passphrase via Argon2id. Strong
     * (memory-hard) but requires the passphrase on every run, which the host
     * application must collect and pass in.
     *
     * The [passphrase] is copied during [Vault.open]; the caller may zero its
     * own array immediately after `open()` returns.
     */
    public data class Passphrase(val passphrase: CharArray) : KeyDerivation {
        // CharArray uses identity equals/hashCode; override so two Passphrase
        // values comparing equal means "same characters", matching intuition and
        // silencing the data-class array footgun.
        override fun equals(other: Any?): Boolean =
            this === other || (other is Passphrase && passphrase.contentEquals(other.passphrase))

        override fun hashCode(): Int = passphrase.contentHashCode()
    }
}
