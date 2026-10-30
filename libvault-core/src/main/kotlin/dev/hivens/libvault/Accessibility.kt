package dev.hivens.libvault

/**
 * When a newly stored secret is readable. Maps to the `kSecAttrAccessible*`
 * constants on macOS Keychain; ignored (honest no-op) on Linux, Windows and
 * Android, where the OS keyring's own lock state governs readability.
 */
public enum class Accessibility {
    /** Readable only while the device is unlocked. The default. */
    WhenUnlocked,

    /** Readable after the first unlock following a boot, then until shutdown. */
    AfterFirstUnlock,

    /** Like [WhenUnlocked], but never copied to another device / backup. */
    WhenUnlockedThisDeviceOnly,

    /** Like [AfterFirstUnlock], but never copied to another device / backup. */
    AfterFirstUnlockThisDeviceOnly,
}
