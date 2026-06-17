package dev.hivens.libvault.linux

import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.internal.SingleThreadVault
import dev.hivens.libvault.internal.openOnDispatchThread
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.util.concurrent.ExecutorService

/**
 * [VaultTier.OsKeyring] on Linux/BSD -- the Freedesktop Secret Service over the
 * D-Bus session bus, spoken directly via [DBusBindings] (libdbus over Panama).
 * Works against any provider: gnome-keyring, KWallet's secret-service bridge,
 * KeePassXC, etc. No runtime libsecret, no dbus-java.
 *
 * **Anti-hang.** Two layers. The connection-and-session setup (and the
 * non-interactive unlock probe) runs inside [openOnDispatchThread], bounded by
 * [VaultConfig.probeTimeoutMs]; every per-op D-Bus round-trip carries libdbus's
 * own reply timeout AND is bounded again by [VaultConfig.opTimeoutMs] in
 * [SingleThreadVault]. The crux: if the default collection is locked and unlocking
 * it would need a UI prompt nobody can answer, setup bails and selection degrades
 * to the file fallback rather than blocking.
 *
 * Secrets use the `"plain"` session algorithm: the value crosses the local Unix
 * domain socket unencrypted (the daemon re-encrypts at rest under the keyring's
 * key). Items are keyed by the `{app, key}` attribute pair and live in the
 * default collection.
 */
internal class SecretServiceVault private constructor(
    executor: ExecutorService,
    opTimeoutMs: Long,
    private val bindings: DBusBindings,
    private val conn: MemorySegment,
    private val session: String,
    private val collection: String,
    private val namespace: String,
    private val replyTimeoutMs: Int,
) : SingleThreadVault(executor, opTimeoutMs, VaultTier.OsKeyring, "secret-service (D-Bus)") {

    private fun attrs(key: String): List<Pair<String, String>> = listOf(ATTR_APP to namespace, ATTR_KEY to key)

    override fun storeRaw(key: String, secret: ByteArray): Boolean {
        val label = "$namespace/$key"
        val (item, prompt) = createItem(bindings, conn, replyTimeoutMs, collection, label, attrs(key), secret, session)
            ?: return false
        return prompt == NO_OBJECT && item != NO_OBJECT
    }

    override fun retrieveRaw(key: String): ByteArray? {
        val (unlocked, locked) = searchItems(bindings, conn, replyTimeoutMs, namespace, key) ?: return null
        val item = unlocked.firstOrNull()
        if (item == null) {
            if (locked.isNotEmpty()) {
                log.info("secret '{}' exists but its collection is locked; not prompting, returning null", key)
            }
            return null
        }
        return getSecret(bindings, conn, replyTimeoutMs, item, session)
    }

    override fun deleteRaw(key: String): Boolean {
        val (unlocked, locked) = searchItems(bindings, conn, replyTimeoutMs, namespace, key) ?: return false
        val items = unlocked + locked
        if (items.isEmpty()) return true // idempotent
        var allRemoved = true
        for (item in items) {
            val prompt = deleteItem(bindings, conn, replyTimeoutMs, item)
            if (prompt != NO_OBJECT) allRemoved = false
        }
        return allRemoved
    }

    override fun containsRaw(key: String): Boolean {
        val (unlocked, locked) = searchItems(bindings, conn, replyTimeoutMs, namespace, key) ?: return false
        return (unlocked + locked).isNotEmpty()
    }

    override fun cleanupRaw() {
        runCatching { closeSession(bindings, conn, replyTimeoutMs, session) }
        runCatching { bindings.handle("dbus_connection_unref").invokeExact(conn) as Unit }
        runCatching { bindings.arena.close() }
    }

    private class Handles(
        val bindings: DBusBindings,
        val conn: MemorySegment,
        val session: String,
        val collection: String,
    )

    companion object {
        private val log: Logger = LoggerFactory.getLogger(SecretServiceVault::class.java)

        private const val SERVICE_NAME = "org.freedesktop.secrets"
        private const val SERVICE_PATH = "/org/freedesktop/secrets"
        private const val IFACE_SERVICE = "org.freedesktop.Secret.Service"
        private const val IFACE_COLLECTION = "org.freedesktop.Secret.Collection"
        private const val IFACE_ITEM = "org.freedesktop.Secret.Item"
        private const val IFACE_SESSION = "org.freedesktop.Secret.Session"
        private const val LABEL_PROP = "org.freedesktop.Secret.Item.Label"
        private const val ATTRS_PROP = "org.freedesktop.Secret.Item.Attributes"
        private const val ATTR_APP = "app"
        private const val ATTR_KEY = "key"
        private const val CONTENT_TYPE = "application/octet-stream"

        /** D-Bus object path "/" -- Secret Service uses it for "no prompt / no object". */
        private const val NO_OBJECT = "/"

        fun create(config: VaultConfig): SecretVault? {
            val replyTimeout = config.opTimeoutMs.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
            val opened = openOnDispatchThread(log, "libvault-secretservice", config.probeTimeoutMs) {
                val bindings = DBusBindings.load() ?: return@openOnDispatchThread null
                val conn = busGet(bindings) ?: run {
                    runCatching { bindings.arena.close() }
                    return@openOnDispatchThread null
                }
                // A bus restart must not _exit() the host process.
                bindings.handle("dbus_connection_set_exit_on_disconnect").invokeExact(conn, 0) as Unit

                val session = openSession(bindings, conn, replyTimeout) ?: run {
                    teardown(bindings, conn)
                    return@openOnDispatchThread null
                }
                val collection = readAliasDefault(bindings, conn, replyTimeout)
                if (collection == null || collection == NO_OBJECT) {
                    log.info("no default secret collection -- treating OS keyring as unavailable")
                    teardown(bindings, conn)
                    return@openOnDispatchThread null
                }
                // Anti-hang crux: a non-interactive unlock. A non-"/" prompt path
                // means an interactive unlock is required, which we refuse to wait on.
                val prompt = unlock(bindings, conn, replyTimeout, listOf(collection))
                if (prompt != NO_OBJECT) {
                    log.info("default collection locked behind an interactive prompt -- degrading to fallback")
                    teardown(bindings, conn)
                    return@openOnDispatchThread null
                }
                Handles(bindings, conn, session, collection)
            } ?: return null

            val (executor, handles) = opened
            return SecretServiceVault(
                executor, config.opTimeoutMs, handles.bindings, handles.conn,
                handles.session, handles.collection, config.namespace, replyTimeout,
            )
        }

        // ── Connection setup ──────────────────────────────────────────────────

        private fun busGet(bindings: DBusBindings): MemorySegment? = Arena.ofConfined().use { setup ->
            val error = setup.allocate(bindings.errorLayout)
            bindings.handle("dbus_error_init").invokeExact(error) as Unit
            val conn = bindings.handle("dbus_bus_get")
                .invokeExact(DBusBindings.DBUS_BUS_SESSION, error) as MemorySegment
            if (conn.address() == 0L) {
                freeErrorIfSet(bindings, error)
                null
            } else {
                conn
            }
        }

        private fun teardown(bindings: DBusBindings, conn: MemorySegment) {
            runCatching { bindings.handle("dbus_connection_unref").invokeExact(conn) as Unit }
            runCatching { bindings.arena.close() }
        }

        private fun freeErrorIfSet(bindings: DBusBindings, error: MemorySegment) {
            if ((bindings.handle("dbus_error_is_set").invokeExact(error) as Int) != 0) {
                runCatching { bindings.handle("dbus_error_free").invokeExact(error) as Unit }
            }
        }

        // ── Protocol methods (all run on the dispatch thread) ──────────────────

        private fun openSession(bindings: DBusBindings, conn: MemorySegment, timeout: Int): String? = transact(
            bindings, conn, timeout, SERVICE_PATH, IFACE_SERVICE, "OpenSession",
            buildArgs = { call, iter ->
                bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, "plain")
                bindings.appendVariantString(call, iter, "") // input variant, empty for "plain"
            },
            readReply = { call, rIter, has ->
                if (!has) {
                    null
                } else {
                    bindings.next(rIter) // skip the output variant, advance to the session path
                    bindings.readText(call, rIter)
                }
            },
        )

        private fun readAliasDefault(bindings: DBusBindings, conn: MemorySegment, timeout: Int): String? = transact(
            bindings, conn, timeout, SERVICE_PATH, IFACE_SERVICE, "ReadAlias",
            buildArgs = { call, iter -> bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, "default") },
            readReply = { call, rIter, has -> if (!has) null else bindings.readText(call, rIter) },
        )

        private fun unlock(bindings: DBusBindings, conn: MemorySegment, timeout: Int, paths: List<String>): String? = transact(
            bindings, conn, timeout, SERVICE_PATH, IFACE_SERVICE, "Unlock",
            buildArgs = { call, iter -> bindings.appendObjectPaths(call, iter, paths) },
            readReply = { call, rIter, has ->
                if (!has) {
                    null
                } else {
                    bindings.next(rIter) // skip the unlocked array, advance to the prompt path
                    bindings.readText(call, rIter)
                }
            },
        )

        private fun searchItems(
            bindings: DBusBindings,
            conn: MemorySegment,
            timeout: Int,
            namespace: String,
            key: String,
        ): Pair<List<String>, List<String>>? = transact(
            bindings, conn, timeout, SERVICE_PATH, IFACE_SERVICE, "SearchItems",
            buildArgs = { call, iter ->
                bindings.appendAttributes(call, iter, listOf(ATTR_APP to namespace, ATTR_KEY to key))
            },
            readReply = { call, rIter, has ->
                if (!has) {
                    null
                } else {
                    val unlocked = bindings.readObjectPaths(call, rIter)
                    bindings.next(rIter)
                    val locked = bindings.readObjectPaths(call, rIter)
                    unlocked to locked
                }
            },
        )

        private fun getSecret(
            bindings: DBusBindings,
            conn: MemorySegment,
            timeout: Int,
            itemPath: String,
            session: String,
        ): ByteArray? = transact(
            bindings, conn, timeout, itemPath, IFACE_ITEM, "GetSecret",
            buildArgs = { call, iter -> bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_OBJECT_PATH, session) },
            readReply = { call, rIter, has -> if (!has) null else bindings.readSecretValue(call, rIter) },
        )

        private fun createItem(
            bindings: DBusBindings,
            conn: MemorySegment,
            timeout: Int,
            collection: String,
            label: String,
            attrs: List<Pair<String, String>>,
            secret: ByteArray,
            session: String,
        ): Pair<String, String>? = transact(
            bindings, conn, timeout, collection, IFACE_COLLECTION, "CreateItem",
            buildArgs = { call, iter ->
                bindings.appendItemProperties(call, iter, LABEL_PROP, label, ATTRS_PROP, attrs)
                bindings.appendSecret(call, iter, session, secret, CONTENT_TYPE)
                bindings.appendBool(call, iter, true) // replace
            },
            readReply = { call, rIter, has ->
                if (!has) {
                    null
                } else {
                    val item = bindings.readText(call, rIter)
                    bindings.next(rIter)
                    val prompt = bindings.readText(call, rIter)
                    if (item == null || prompt == null) null else item to prompt
                }
            },
        )

        private fun deleteItem(bindings: DBusBindings, conn: MemorySegment, timeout: Int, itemPath: String): String? = transact(
            bindings, conn, timeout, itemPath, IFACE_ITEM, "Delete",
            buildArgs = { _, _ -> },
            readReply = { call, rIter, has -> if (!has) null else bindings.readText(call, rIter) },
        )

        private fun closeSession(bindings: DBusBindings, conn: MemorySegment, timeout: Int, session: String) {
            transact<Unit>(
                bindings, conn, timeout, session, IFACE_SESSION, "Close",
                buildArgs = { _, _ -> },
                readReply = { _, _, _ -> Unit },
            )
        }

        /**
         * One blocking D-Bus method call against [SERVICE_NAME]. Builds the
         * argument list with [buildArgs], blocks for the reply (libdbus-side
         * [timeout]), hands the reply iterator to [readReply], and frees both
         * messages. Returns null on any libdbus failure (no reply, bad message).
         */
        private fun <T> transact(
            bindings: DBusBindings,
            conn: MemorySegment,
            timeout: Int,
            path: String,
            iface: String,
            member: String,
            buildArgs: (Arena, MemorySegment) -> Unit,
            readReply: (Arena, MemorySegment, Boolean) -> T?,
        ): T? {
            Arena.ofConfined().use { call ->
                val msg = bindings.handle("dbus_message_new_method_call").invokeExact(
                    call.allocateUtf8(SERVICE_NAME),
                    call.allocateUtf8(path),
                    call.allocateUtf8(iface),
                    call.allocateUtf8(member),
                ) as MemorySegment
                if (msg.address() == 0L) return null
                try {
                    val iter = bindings.scratchIter(call)
                    bindings.handle("dbus_message_iter_init_append").invokeExact(msg, iter) as Unit
                    buildArgs(call, iter)

                    val error = call.allocate(bindings.errorLayout)
                    bindings.handle("dbus_error_init").invokeExact(error) as Unit
                    val reply = bindings.handle("dbus_connection_send_with_reply_and_block")
                        .invokeExact(conn, msg, timeout, error) as MemorySegment
                    if (reply.address() == 0L) {
                        freeErrorIfSet(bindings, error)
                        return null
                    }
                    try {
                        val rIter = bindings.scratchIter(call)
                        val has = (bindings.handle("dbus_message_iter_init").invokeExact(reply, rIter) as Int) != 0
                        return readReply(call, rIter, has)
                    } finally {
                        runCatching { bindings.handle("dbus_message_unref").invokeExact(reply) as Unit }
                    }
                } finally {
                    runCatching { bindings.handle("dbus_message_unref").invokeExact(msg) as Unit }
                }
            }
        }
    }
}
