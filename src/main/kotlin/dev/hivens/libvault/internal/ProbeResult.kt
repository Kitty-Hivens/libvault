package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultAvailability

/**
 * What an OS-keyring backend's `create` reports: either an opened vault, or the
 * reason it couldn't open. Lets [VaultSelector] both pick a backend AND answer
 * [dev.hivens.libvault.Vault.probe]'s "why not?" without a second code path.
 */
internal sealed interface ProbeResult {
    data class Opened(val vault: SecretVault) : ProbeResult
    data class Unavailable(val availability: VaultAvailability) : ProbeResult
}
