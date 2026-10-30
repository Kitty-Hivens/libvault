package dev.hivens.libvault.internal

import java.nio.file.Files
import java.nio.file.Path

/**
 * A stable, machine-and-user-local seed string for the [MachineBound][dev.hivens.libvault.KeyDerivation.MachineBound]
 * key derivation. The same machine + user reproduce the same seed across runs;
 * a different machine or user produces a different one. This is the basis for
 * obfuscation-grade encryption -- NOT protection, since anything running as this
 * user can read the same inputs.
 */
internal object MachineId {

    /** Build the seed once. Cheap and side-effect free; callers may cache it. */
    fun seed(): String = buildString {
        append(System.getProperty("user.name", "unknown"))
        append('|')
        append(System.getProperty("user.home", "/"))
        append('|')
        append(System.getProperty("os.name", ""))
        append('|')
        append(System.getProperty("os.arch", ""))
        append('|')
        append(stableHostId())
    }

    /**
     * A per-host identifier that survives reboots. Linux exposes a real one in
     * `/etc/machine-id` (or the dbus mirror); elsewhere fall back to the
     * hostname from the environment, then to a constant so the seed is always
     * well-formed even on a stripped host.
     */
    private fun stableHostId(): String {
        readFirstLine(Path.of("/etc/machine-id"))?.let { return it }
        readFirstLine(Path.of("/var/lib/dbus/machine-id"))?.let { return it }
        readFirstLine(Path.of("/proc/sys/kernel/hostname"))?.let { return it }
        sequenceOf("HOSTNAME", "COMPUTERNAME")
            .mapNotNull { System.getenv(it)?.trim()?.ifBlank { null } }
            .firstOrNull()
            ?.let { return it }
        return "no-host-id"
    }

    private fun readFirstLine(path: Path): String? = runCatching {
        if (!Files.isReadable(path)) return null
        Files.readAllLines(path).firstOrNull()?.trim()?.ifBlank { null }
    }.getOrNull()
}
