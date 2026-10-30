package dev.hivens.libvault.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.asDescribable
import dev.hivens.libvault.asEnumerable
import dev.hivens.libvault.asLabeled
import dev.hivens.libvault.asMigratable
import dev.hivens.libvault.asUnlockable
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The Android backend against the device's real Keystore. Each test works in a
 * namespace of its own and removes its keys and files afterwards.
 */
@RunWith(AndroidJUnit4::class)
class AndroidVaultTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val namespace = "dev.hivens.libvault.test.${System.nanoTime()}"
    private val collections = mutableSetOf<String?>(null)

    private fun config(
        collection: String? = null,
        tiers: List<VaultTier> = listOf(VaultTier.OsKeyring),
    ): VaultConfig {
        collections += collection
        // Generous: the first open generates a key, which a slow Keystore may
        // take a while over, and the tests are about behaviour, not latency.
        return VaultConfig(namespace, collection = collection, preferredTiers = tiers, probeTimeoutMs = 10_000, opTimeoutMs = 10_000)
    }

    private fun open(collection: String? = null): SecretVault = AndroidVault.open(context, config(collection))

    private val namespaceDir: File get() = KeystoreVault.namespaceDir(context.noBackupFilesDir, namespace)

    @After
    fun cleanUp() {
        val keyStore = KeystoreFileKey.keyStore()
        for (collection in collections) {
            keyStore.deleteEntry(KeystoreVault.aliasOf(namespace, collection))
        }
        namespaceDir.deleteRecursively()
    }

    @Test
    fun opensTheKeystoreTierAndRoundTrips() {
        open().use { vault ->
            assertEquals(VaultTier.OsKeyring, vault.tier)
            assertEquals(KeystoreVault.BACKEND, vault.backend)
            assertTrue(vault.secure)

            val blob = ByteArray(256) { it.toByte() }
            assertTrue(vault.store("blob", blob))
            assertArrayEquals(blob, vault.retrieve("blob"))
            assertTrue(vault.contains("blob"))

            assertTrue(vault.delete("blob"))
            assertFalse(vault.contains("blob"))
            assertNull(vault.retrieve("blob"))
            assertTrue(vault.delete("blob"))
        }
    }

    @Test
    fun secretsSurviveAReopen() {
        open().use { assertTrue(it.storeString("pw", "пароль".toCharArray())) }
        open().use { assertEquals("пароль", String(it.retrieveString("pw")!!)) }
    }

    @Test
    fun theFileHoldsCiphertextOnly() {
        val secret = "plain-marker-${System.nanoTime()}"
        open().use { assertTrue(it.store("k", secret.toByteArray())) }
        val bytes = File(namespaceDir, "keystore.bin").readBytes()
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains(secret))
    }

    @Test
    fun capabilities() {
        open().use { vault ->
            val labeled = vault.asLabeled()!!
            assertTrue(labeled.store("a", "1".toByteArray(), label = "Label A", attributes = mapOf("kind" to "token")))
            assertTrue(vault.store("b", "2".toByteArray()))

            val meta = vault.asDescribable()!!.describe("a")!!
            assertEquals("Label A", meta.label)
            assertEquals(mapOf("kind" to "token"), meta.attributes)
            assertNotNull(meta.created)

            val unlockable = vault.asUnlockable()!!
            assertFalse(unlockable.isLocked())

            val enumerable = vault.asEnumerable()!!
            assertEquals(setOf("a", "b"), enumerable.list().toSet())
            assertEquals(2, enumerable.clear())
            assertEquals(emptyList<String>(), enumerable.list())
        }
    }

    @Test
    fun migratesIntoAnotherTier() {
        val memory = AndroidVault.open(context, config(tiers = listOf(VaultTier.Memory)))
        open().use { vault ->
            vault.store("a", "1".toByteArray())
            val report = vault.asMigratable()!!.migrateTo(memory, deleteAfter = true)
            assertTrue(report.complete)
            assertEquals("1", memory.retrieve("a")!!.decodeToString())
            assertFalse(vault.contains("a"))
        }
        memory.close()
    }

    @Test
    fun aCollectionHasItsOwnKeyAndFile() {
        open().use { it.store("k", "default".toByteArray()) }
        open("work").use { work ->
            assertNull(work.retrieve("k"))
            work.store("k", "work".toByteArray())
        }
        open().use { assertEquals("default", it.retrieve("k")!!.decodeToString()) }
        open("work").use { assertEquals("work", it.retrieve("k")!!.decodeToString()) }
        assertTrue(File(namespaceDir, "keystore-work.bin").isFile)
    }

    @Test
    fun aLostKeyMovesTheFileAsideInsteadOfOverwritingIt() {
        open().use { it.store("old", "1".toByteArray()) }
        KeystoreFileKey.keyStore().deleteEntry(KeystoreVault.aliasOf(namespace, null))

        open().use { vault ->
            assertNull(vault.retrieve("old"))
            assertTrue(vault.store("new", "2".toByteArray()))
            assertEquals("2", vault.retrieve("new")!!.decodeToString())
        }
        val aside = namespaceDir.listFiles()!!.filter { it.name.startsWith("keystore.bin.unreadable-") }
        assertEquals(1, aside.size)
    }

    @Test
    fun probeReportsTheKeystoreAvailable() {
        val statuses = AndroidVault.probe(context, config(tiers = listOf(VaultTier.OsKeyring, VaultTier.SoftwareFile)))
        assertEquals(listOf(VaultTier.OsKeyring, VaultTier.SoftwareFile), statuses.map { it.tier })
        assertEquals(VaultAvailability.Available, statuses[0].availability)
        assertEquals(KeystoreVault.BACKEND, statuses[0].backend)
    }

    @Test
    fun probeLeavesNoKeyBehind() {
        AndroidVault.probe(context, config())
        assertFalse(KeystoreFileKey.keyStore().containsAlias(KeystoreVault.aliasOf(namespace, null)))
    }

    @Test
    fun theKeyIsMadeByTheFirstWriteNotByOpening() {
        val alias = KeystoreVault.aliasOf(namespace, null)
        open().use { vault ->
            assertFalse(KeystoreFileKey.keyStore().containsAlias(alias))
            assertTrue(vault.store("k", "v".toByteArray()))
            assertTrue(KeystoreFileKey.keyStore().containsAlias(alias))
        }
    }

    @Test
    fun aNameTooLongForAFileStillStores() {
        // Nine bytes per character once URL-encoded: far past the 255-byte limit.
        val collection = "коллекция".repeat(40)
        open(collection).use { vault ->
            assertTrue(vault.store("k", "v".toByteArray()))
            assertEquals("v", vault.retrieve("k")!!.decodeToString())
        }
    }

    @Test
    fun theSoftwareTierDefaultsToTheNoBackupDirectory() {
        AndroidVault.open(context, config(tiers = listOf(VaultTier.SoftwareFile))).use { vault ->
            assertEquals(VaultTier.SoftwareFile, vault.tier)
            assertFalse(vault.secure)
            assertTrue(vault.store("k", "v".toByteArray()))
        }
        assertTrue(File(namespaceDir, "vault.bin").isFile)
    }
}
