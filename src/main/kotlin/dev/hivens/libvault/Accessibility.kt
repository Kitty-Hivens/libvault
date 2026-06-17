package dev.hivens.libvault

/**
 * When a newly stored secret is readable. Maps to the `kSecAttrAccessible*`
 * constants on macOS Keychain; ignored (honest no-op) on Linux and Windows,
 * where the OS keyring's own lock state governs readability.
 */
public enum class Accessibility(internal val cfConstantName: String) {
    /** Readable only while the device is unlocked. The default. */
    WhenUnlocked("kSecAttrAccessibleWhenUnlocked"),

    /** Readable after the first unlock following a boot, then until shutdown. */
    AfterFirstUnlock("kSecAttrAccessibleAfterFirstUnlock"),

    /** Like [WhenUnlocked], but never copied to another device / backup. */
    WhenUnlockedThisDeviceOnly("kSecAttrAccessibleWhenUnlockedThisDeviceOnly"),

    /** Like [AfterFirstUnlock], but never copied to another device / backup. */
    AfterFirstUnlockThisDeviceOnly("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"),
}
