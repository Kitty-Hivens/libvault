package dev.hivens.libvault.internal

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultAvailability

/**
 * What an OS-keyring backend's `create` reports: either an opened vault, or the
 * reason it couldn't open. Lets [VaultSelector] both pick a backend AND answer
 * a probe's "why not?" without a second code path.
 */
@InternalLibvaultApi
public sealed interface ProbeResult {
    public data class Opened(public val vault: SecretVault) : ProbeResult
    public data class Unavailable(public val availability: VaultAvailability) : ProbeResult
}
