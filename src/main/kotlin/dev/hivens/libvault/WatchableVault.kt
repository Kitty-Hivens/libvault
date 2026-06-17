package dev.hivens.libvault

/**
 * A [SecretVault] that can report external modifications to its namespace.
 * Discover with [asWatchable]. Real on Linux Secret Service (Item signals);
 * Windows and macOS return an inert subscription (no change feed). Callbacks run
 * on a backend-owned thread -- hop to your own dispatcher before touching UI.
 */
public interface WatchableVault {
    /**
     * Register [callback] for change events. The returned [AutoCloseable]
     * unsubscribes when closed; idempotent. Closing the vault also unsubscribes.
     */
    public fun onWatch(callback: (VaultChange) -> Unit): AutoCloseable
}
