package dev.hivens.libvault.internal

import java.nio.file.Path

/**
 * Resolves the default per-user data directory for the software-file tier when
 * [dev.hivens.libvault.VaultConfig.softwareFilePath] is left null. Follows each
 * platform's convention so the blob lands where users expect app data.
 */
internal object DataDir {

    fun resolve(namespace: String, fileName: String = "vault.bin"): Path =
        base().resolve(namespace).resolve(fileName)

    private fun base(): Path {
        val os = System.getProperty("os.name", "").lowercase()
        val home = System.getProperty("user.home", ".")
        return when {
            os.contains("win") -> {
                val local = System.getenv("LOCALAPPDATA")?.ifBlank { null }
                if (local != null) Path.of(local) else Path.of(home, "AppData", "Local")
            }
            os.contains("mac") || os.contains("darwin") ->
                Path.of(home, "Library", "Application Support")
            else -> {
                val xdg = System.getenv("XDG_DATA_HOME")?.ifBlank { null }
                if (xdg != null) Path.of(xdg) else Path.of(home, ".local", "share")
            }
        }
    }
}
