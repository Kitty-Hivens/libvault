package dev.hivens.libvault

/**
 * A [SecretVault] that can attach a human [label] and extra searchable
 * [attributes][store] when storing. The label shows in OS tools (seahorse,
 * Keychain Access); both are ignored where the backend can't carry them.
 * Discover with [asLabeled].
 */
public interface LabeledVault {
    /**
     * Like [SecretVault.store], but with a display label and extra attributes.
     * The reserved scoping attributes (app/key) are added by the backend; the
     * supplied [attributes] must not collide with them (those are dropped).
     */
    public fun store(
        key: String,
        secret: ByteArray,
        label: String? = null,
        attributes: Map<String, String> = emptyMap(),
    ): Boolean
}
