package dev.hivens.libvault.internal

import dev.hivens.libvault.VaultConfig

/**
 * The OS keyring of one platform, as [VaultSelector] sees it. libvault (desktop)
 * picks Secret Service, Credential Manager or Keychain by OS and registers
 * itself as a ServiceLoader service, which `Vault` finds. libvault-android
 * hands the Android Keystore to the selector directly, since it needs a
 * `Context`.
 */
@InternalLibvaultApi
public interface KeyringBackend {
    /** Backend label reported by a probe when the keyring could not open. */
    public val label: String

    /** Open the keyring for [config], or say why it cannot. May throw, the selector degrades on it. */
    public fun open(config: VaultConfig): ProbeResult

    /** Labels of the keyring's separately lockable collections. Empty where there are none. */
    public fun collections(config: VaultConfig): List<String> = emptyList()
}
