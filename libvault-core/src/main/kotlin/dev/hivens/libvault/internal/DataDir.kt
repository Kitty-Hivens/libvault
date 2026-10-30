package dev.hivens.libvault.internal

import java.nio.file.Path
import java.nio.file.Paths

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
                if (local != null) Paths.get(local) else Paths.get(home, "AppData", "Local")
            }
            os.contains("mac") || os.contains("darwin") ->
                Paths.get(home, "Library", "Application Support")
            else -> {
                val xdg = System.getenv("XDG_DATA_HOME")?.ifBlank { null }
                if (xdg != null) Paths.get(xdg) else Paths.get(home, ".local", "share")
            }
        }
    }
}
