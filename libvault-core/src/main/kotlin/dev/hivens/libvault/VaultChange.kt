package dev.hivens.libvault

/** What happened to an entry, as reported by [WatchableVault.onWatch]. */
public enum class ChangeKind { Created, Modified, Deleted }

/**
 * An external modification to the vault's namespace, delivered to an
 * [WatchableVault.onWatch] callback (e.g. a secret edited in seahorse or wiped
 * by another app).
 *
 * [key] is best-effort: for [ChangeKind.Deleted] the item is already gone and its
 * attributes can't be read back, so the key is often null. Callers that need to
 * re-sync should re-[read][SecretVault.retrieve] the keys they care about rather
 * than trust the key field exhaustively.
 */
public data class VaultChange(
    public val key: String?,
    public val kind: ChangeKind,
)
