package dev.hivens.libvault.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.hivens.libvault.internal.FileKey
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * An AES-256-GCM key that lives in the Android Keystore under [alias] and never
 * leaves it: the vault file holds only what this key encrypted, and the
 * Keystore (in the TEE where the device has one) does every encryption and
 * decryption.
 *
 * There is no salt, the alias names the key. A file whose key is gone (app data
 * restored without it, a Keystore reset) fails its verifier and is moved aside
 * by the vault, and [newKey] then creates a fresh key for the new file.
 */
internal class KeystoreFileKey(private val alias: String) : FileKey {

    override val kdfId: Int = FileKey.ANDROID_KEYSTORE
    override val saltLength: Int = 0

    override fun keyFor(salt: ByteArray): SecretKey? = existing()

    /**
     * The existing key when there is one. A file set aside because it was
     * corrupt, not because its key was lost, stays readable that way.
     */
    override fun newKey(salt: ByteArray): SecretKey = existing() ?: generate(alias)

    override fun close() {
        // The key never enters this process, so there is nothing here to forget.
    }

    private fun existing(): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    internal companion object {
        private const val PROVIDER = "AndroidKeyStore"

        fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

        fun generate(alias: String): SecretKey {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
                .apply { init(spec) }
                .generateKey()
        }
    }
}
