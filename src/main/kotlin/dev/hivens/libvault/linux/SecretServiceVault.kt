package dev.hivens.libvault.linux

import dev.hivens.libvault.ChangeKind
import dev.hivens.libvault.DescribableVault
import dev.hivens.libvault.EntryMetadata
import dev.hivens.libvault.EnumerableVault
import dev.hivens.libvault.LabeledVault
import dev.hivens.libvault.MigratableVault
import dev.hivens.libvault.MigrationReport
import dev.hivens.libvault.SecretVault
import dev.hivens.libvault.UnlockPolicy
import dev.hivens.libvault.UnlockableVault
import dev.hivens.libvault.VaultAvailability
import dev.hivens.libvault.VaultChange
import dev.hivens.libvault.VaultConfig
import dev.hivens.libvault.VaultTier
import dev.hivens.libvault.WatchableVault
import dev.hivens.libvault.internal.Migrator
import dev.hivens.libvault.internal.ProbeResult
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * [VaultTier.OsKeyring] on Linux/BSD -- Freedesktop Secret Service over the D-Bus
 * session bus, spoken directly via [DBusBindings] (libdbus over Panama). No
 * runtime libsecret, no dbus-java.
 *
 * Threading mirrors libnotify's notifier: ONE owned dispatch thread holds the
 * (not-thread-safe) libdbus connection. Public ops enqueue a task + a future; the
 * caller waits bounded (`opTimeoutMs`, or `unlockTimeoutMs` for [unlock]). Between
 * tasks the thread drains incoming signals to feed [onWatch] callbacks and to
 * catch the unlock prompt's `Completed`. Bounded ops, a persistent watch, and a
 * transient unlock pump thus coexist on one connection-safe thread.
 *
 * Default [Vault.open] never prompts: a locked collection makes setup report
 * [VaultAvailability.Locked] and the selector degrades. Only [UnlockPolicy.IfLocked]
 * (or an explicit [unlock]) surfaces a prompt.
 *
 * Secrets use the `"plain"` session algorithm (value crosses the local socket
 * unencrypted; the daemon re-encrypts at rest). Items are keyed by `{app, key}`
 * attributes in the target collection.
 */
internal class SecretServiceVault private constructor(
    private val bindings: DBusBindings,
    private val namespace: String,
    private val collectionLabel: String?,
    private val replyTimeoutMs: Int,
    private val unlockTimeoutMs: Int,
    private val unlockPolicy: UnlockPolicy,
) : SecretVault, EnumerableVault, DescribableVault, LabeledVault, UnlockableVault, WatchableVault, MigratableVault {

    override val tier: VaultTier = VaultTier.OsKeyring
    override val backend: String = "secret-service (D-Bus)"

    private val open = AtomicBoolean(true)
    private val tornDown = AtomicBoolean(false)
    private val setupResult = CompletableFuture<VaultAvailability>()
    private val tasks = LinkedBlockingQueue<Runnable>()
    private val watchers = CopyOnWriteArrayList<(VaultChange) -> Unit>()

    // Touched only on the dispatch thread (setup + ops + signal drain all run there).
    private var conn: MemorySegment? = null
    private var session: String = NO_OBJECT
    private var collection: String = NO_OBJECT
    private var watchActive = false
    private var activePromptPath: String? = null
    private var unlockSignalled = false
    private var unlockGranted = false
    private val itemKeyCache = ConcurrentHashMap<String, String>()

    private val dispatchThread = Thread({ run() }, "libvault-secretservice-${ProcessHandle.current().pid()}")
        .apply { isDaemon = true }

    init {
        dispatchThread.start()
    }

    // ── Public API (enqueue onto the dispatch thread, bounded) ────────────────

    override fun store(key: String, secret: ByteArray): Boolean = store(key, secret, null, emptyMap())

    override fun store(key: String, secret: ByteArray, label: String?, attributes: Map<String, String>): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false, replyTimeoutMs) {
            createItemImpl(key, label ?: "$namespace/$key", attributes, secret)
        }
    }

    override fun retrieve(key: String): ByteArray? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null, replyTimeoutMs) { retrieveImpl(key) }
    }

    override fun delete(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false, replyTimeoutMs) { deleteImpl(key) }
    }

    override fun contains(key: String): Boolean {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(false, replyTimeoutMs) {
            val (u, l) = searchItems(attrsOf(key)) ?: return@bounded false
            (u + l).isNotEmpty()
        }
    }

    override fun list(): List<String> = bounded(emptyList(), replyTimeoutMs) { listKeys() }

    override fun clear(): Int = bounded(-1, replyTimeoutMs) { clearImpl() }

    override fun describe(key: String): EntryMetadata? {
        require(key.isNotBlank()) { "key must be non-blank" }
        return bounded(null, replyTimeoutMs) { describeImpl(key) }
    }

    override fun isLocked(): Boolean = bounded(true, replyTimeoutMs) {
        getBoolProperty(collection, IFACE_COLLECTION, "Locked") ?: true
    }

    override fun unlock(): Boolean = bounded(false, unlockTimeoutMs.toLong()) {
        val prompt = serviceUnlock(listOf(collection)) ?: return@bounded false
        if (prompt == NO_OBJECT) true else promptAndPump(prompt)
    }

    override fun lock(): Boolean = bounded(false, replyTimeoutMs) {
        val prompt = lockImpl(listOf(collection)) ?: return@bounded false
        prompt == NO_OBJECT
    }

    override fun migrateTo(target: SecretVault, deleteAfter: Boolean): MigrationReport =
        Migrator.migrate(this, target, deleteAfter)

    override fun onWatch(callback: (VaultChange) -> Unit): AutoCloseable {
        bounded(Unit, replyTimeoutMs.toLong()) {
            if (!watchActive) {
                addMatch("type='signal',interface='$IFACE_COLLECTION',path='$collection'")
                watchActive = true
            }
        }
        watchers.add(callback)
        return AutoCloseable { watchers.remove(callback) }
    }

    override fun close() {
        if (!open.compareAndSet(true, false)) return
        runCatching { dispatchThread.join(replyTimeoutMs.toLong() + 1_000) }
        teardown()
    }

    private fun <T> bounded(default: T, timeoutMs: Int, op: () -> T): T = bounded(default, timeoutMs.toLong(), op)

    private fun <T> bounded(default: T, timeoutMs: Long, op: () -> T): T {
        if (!open.get()) return default
        val future = CompletableFuture<T>()
        tasks.add(Runnable { future.complete(runCatching { op() }.getOrElse { log.warn("op failed: {}", it.message); default }) })
        return runCatching { future.get(timeoutMs, TimeUnit.MILLISECONDS) }.getOrElse { e ->
            // Restore the interrupt flag so a cancelled caller still sees it.
            if (e is InterruptedException) Thread.currentThread().interrupt()
            if (e is TimeoutException) {
                log.warn("secret-service op exceeded {} ms -- degrading", timeoutMs)
            } else {
                log.warn("secret-service op did not complete: {}", e.message ?: e.javaClass.simpleName)
            }
            default
        }
    }

    // ── Dispatch thread ───────────────────────────────────────────────────────

    private fun run() {
        try {
            doSetup()
            if (!open.get()) {
                teardown()
                return
            }
            dispatchLoop()
        } catch (t: Throwable) {
            // An unexpected throw on the dispatch thread (e.g. a Panama
            // WrongMethodType, OOM) must still complete setup and free the arena,
            // or create() waits the full budget and the libdbus handle leaks.
            log.warn("secret-service dispatch thread crashed: {}", t.message ?: t.javaClass.simpleName)
            runCatching { failSetup(VaultAvailability.ServiceUnavailable) }
            teardown()
        }
    }

    private fun doSetup() {
        val c = busGet()
        if (c == null) {
            failSetup(VaultAvailability.ServiceUnavailable); return
        }
        conn = c
        runCatching { bindings.handle("dbus_connection_set_exit_on_disconnect").invokeExact(c, 0) as Unit }

        val s = openSession()
        if (s == null) {
            failSetup(VaultAvailability.ServiceUnavailable); return
        }
        session = s

        val coll = resolveCollection()
        if (coll == null || coll == NO_OBJECT) {
            failSetup(VaultAvailability.ServiceUnavailable); return
        }
        collection = coll

        val prompt = serviceUnlock(listOf(coll))
        if (prompt == null) {
            failSetup(VaultAvailability.ServiceUnavailable); return
        }
        if (prompt != NO_OBJECT) {
            if (unlockPolicy == UnlockPolicy.IfLocked && promptAndPump(prompt)) {
                setupResult.complete(VaultAvailability.Available)
            } else {
                failSetup(VaultAvailability.Locked)
            }
            return
        }
        setupResult.complete(VaultAvailability.Available)
    }

    private fun failSetup(availability: VaultAvailability) {
        open.set(false)
        setupResult.complete(availability)
    }

    private fun dispatchLoop() {
        val readWrite = bindings.handle("dbus_connection_read_write")
        val c = conn ?: return
        while (open.get()) {
            try {
                var task: Runnable? = tasks.poll(25, TimeUnit.MILLISECONDS)
                while (task != null) {
                    runCatching { task.run() }
                    task = tasks.poll()
                }
                readWrite.invokeExact(c, 0) as Int
                drainSignals()
            } catch (t: Throwable) {
                log.warn("secret-service dispatch iteration threw: {}", t.message)
                runCatching { Thread.sleep(200) }
            }
        }
    }

    private fun drainSignals() {
        val pop = bindings.handle("dbus_connection_pop_message")
        val unref = bindings.handle("dbus_message_unref")
        val c = conn ?: return
        while (open.get()) {
            val msg = pop.invokeExact(c) as MemorySegment
            if (msg.address() == 0L) break
            try {
                dispatchSignal(msg)
            } catch (t: Throwable) {
                log.warn("signal dispatch threw, dropping: {}", t.message)
            } finally {
                runCatching { unref.invokeExact(msg) as Unit }
            }
        }
    }

    private fun dispatchSignal(msg: MemorySegment) {
        if ((bindings.handle("dbus_message_get_type").invokeExact(msg) as Int) != DBusBindings.DBUS_MESSAGE_TYPE_SIGNAL) return
        val iface = bindings.readMessageString("dbus_message_get_interface", msg) ?: return
        val member = bindings.readMessageString("dbus_message_get_member", msg) ?: return
        val path = bindings.readMessageString("dbus_message_get_path", msg)

        if (iface == IFACE_PROMPT && member == "Completed" && path == activePromptPath) {
            Arena.ofConfined().use { call ->
                val iter = bindings.scratchIter(call)
                if ((bindings.handle("dbus_message_iter_init").invokeExact(msg, iter) as Int) != 0) {
                    // Completed(dismissed: b, result: v)
                    val out = call.allocate(ValueLayout.JAVA_INT)
                    bindings.handle("dbus_message_iter_get_basic").invokeExact(iter, out) as Unit
                    unlockGranted = out.get(ValueLayout.JAVA_INT, 0) == 0 // dismissed == false -> granted
                }
            }
            unlockSignalled = true
            return
        }

        if (iface == IFACE_COLLECTION && watchers.isNotEmpty()) {
            val kind = when (member) {
                "ItemCreated" -> ChangeKind.Created
                "ItemChanged" -> ChangeKind.Modified
                "ItemDeleted" -> ChangeKind.Deleted
                else -> return
            }
            val itemPath = Arena.ofConfined().use { call ->
                val iter = bindings.scratchIter(call)
                if ((bindings.handle("dbus_message_iter_init").invokeExact(msg, iter) as Int) == 0) null
                else bindings.readText(call, iter)
            }
            val key = itemPath?.let { itemKeyCache[it] }
            if (kind == ChangeKind.Deleted) itemPath?.let { itemKeyCache.remove(it) }
            fireWatch(VaultChange(key, kind))
        }
    }

    private fun fireWatch(change: VaultChange) {
        for (w in watchers) runCatching { w(change) }.onFailure { log.warn("watch handler threw: {}", it.message) }
    }

    private fun teardown() {
        if (!tornDown.compareAndSet(false, true)) return
        val c = conn
        if (c != null) {
            runCatching { closeSession() }
            runCatching { bindings.handle("dbus_connection_unref").invokeExact(c) as Unit }
        }
        runCatching { bindings.arena.close() }
    }

    // ── Op implementations (run on the dispatch thread) ───────────────────────

    private fun attrsOf(key: String): List<Pair<String, String>> = listOf(ATTR_APP to namespace, ATTR_KEY to key)

    private fun createItemImpl(key: String, label: String, userAttrs: Map<String, String>, secret: ByteArray): Boolean {
        val attrs = attrsOf(key) + userAttrs.filterKeys { it != ATTR_APP && it != ATTR_KEY }.toList()
        val (item, prompt) = createItem(collection, label, attrs, secret) ?: return false
        if (prompt == NO_OBJECT && item != NO_OBJECT) {
            itemKeyCache[item] = key
            return true
        }
        return false
    }

    private fun retrieveImpl(key: String): ByteArray? {
        val (unlocked, locked) = searchItems(attrsOf(key)) ?: return null
        val item = unlocked.firstOrNull()
        if (item == null) {
            if (locked.isNotEmpty()) log.info("secret '{}' present but its collection is locked", key)
            return null
        }
        itemKeyCache[item] = key
        return getSecret(item)
    }

    private fun deleteImpl(key: String): Boolean {
        val (unlocked, locked) = searchItems(attrsOf(key)) ?: return false
        val items = unlocked + locked
        if (items.isEmpty()) return true
        var allRemoved = true
        for (item in items) {
            val prompt = deleteItem(item)
            if (prompt != NO_OBJECT) allRemoved = false else itemKeyCache.remove(item)
        }
        return allRemoved
    }

    private fun listKeys(): List<String> {
        val (unlocked, locked) = searchItems(listOf(ATTR_APP to namespace)) ?: return emptyList()
        val keys = ArrayList<String>()
        for (item in unlocked + locked) {
            val attrs = getAttributesProperty(item)
            val k = attrs?.get(ATTR_KEY) ?: continue
            itemKeyCache[item] = k
            keys += k
        }
        return keys
    }

    private fun clearImpl(): Int {
        val (unlocked, locked) = searchItems(listOf(ATTR_APP to namespace)) ?: return -1
        val items = unlocked + locked
        var removed = 0
        for (item in items) {
            if (deleteItem(item) == NO_OBJECT) {
                removed++
                itemKeyCache.remove(item)
            }
        }
        return removed
    }

    private fun describeImpl(key: String): EntryMetadata? {
        val (unlocked, locked) = searchItems(attrsOf(key)) ?: return null
        val item = (unlocked + locked).firstOrNull() ?: return null
        val label = getStringProperty(item, IFACE_ITEM, "Label")
        val created = getUInt64Property(item, IFACE_ITEM, "Created")?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) }
        val modified = getUInt64Property(item, IFACE_ITEM, "Modified")?.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) }
        val attrs = getAttributesProperty(item)?.filterKeys { it != ATTR_APP && it != ATTR_KEY }.orEmpty()
        return EntryMetadata(label, created, modified, attrs)
    }

    // ── Collection resolution ─────────────────────────────────────────────────

    private fun resolveCollection(): String? {
        if (collectionLabel == null) return readAliasDefault()
        findCollectionByLabel(collectionLabel)?.let { return it }
        return createCollection(collectionLabel)
    }

    private fun findCollectionByLabel(label: String): String? {
        val collections = getObjectPathsProperty(SERVICE_PATH, IFACE_SERVICE, "Collections") ?: return null
        return collections.firstOrNull { getStringProperty(it, IFACE_COLLECTION, "Label") == label }
    }

    private fun createCollection(label: String): String? = transact(
        SERVICE_PATH, IFACE_SERVICE, "CreateCollection",
        buildArgs = { call, iter ->
            bindings.appendCollectionProperties(call, iter, COLLECTION_LABEL_PROP, label)
            bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, "") // no alias
        },
        readReply = { call, rIter, has ->
            if (!has) {
                null
            } else {
                val coll = bindings.readText(call, rIter)
                bindings.next(rIter)
                val prompt = bindings.readText(call, rIter)
                if (coll != null && coll != NO_OBJECT && prompt == NO_OBJECT) coll else null
            }
        },
    )

    fun collectionLabels(): List<String> = bounded(emptyList<String>(), replyTimeoutMs.toLong()) {
        // MUST run on the dispatch thread: it touches `conn`, which the loop is
        // concurrently draining. Every other op already routes through bounded().
        val collections = getObjectPathsProperty(SERVICE_PATH, IFACE_SERVICE, "Collections")
            ?: return@bounded emptyList()
        collections.mapNotNull { getStringProperty(it, IFACE_COLLECTION, "Label") }
    }

    // ── Unlock prompt pump (runs on the dispatch thread) ──────────────────────

    private fun promptAndPump(promptPath: String): Boolean {
        addMatch("type='signal',interface='$IFACE_PROMPT',path='$promptPath'")
        activePromptPath = promptPath
        unlockSignalled = false
        unlockGranted = false
        val prompted = transact<Boolean>(
            promptPath, IFACE_PROMPT, "Prompt",
            buildArgs = { call, iter -> bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, "") },
            readReply = { _, _, _ -> true },
        )
        if (prompted != true) {
            activePromptPath = null
            return false
        }
        val readWrite = bindings.handle("dbus_connection_read_write")
        val c = conn ?: return false
        val deadline = System.nanoTime() + unlockTimeoutMs.toLong() * 1_000_000
        while (open.get() && System.nanoTime() < deadline) {
            readWrite.invokeExact(c, 100) as Int
            drainSignals()
            if (unlockSignalled) break
        }
        activePromptPath = null
        return unlockSignalled && unlockGranted
    }

    // ── Secret Service protocol (blocking method calls) ───────────────────────

    private fun busGet(): MemorySegment? = Arena.ofConfined().use { setup ->
        val error = setup.allocate(bindings.errorLayout)
        bindings.handle("dbus_error_init").invokeExact(error) as Unit
        val c = bindings.handle("dbus_bus_get").invokeExact(DBusBindings.DBUS_BUS_SESSION, error) as MemorySegment
        if (c.address() == 0L) {
            freeErrorIfSet(error); null
        } else {
            c
        }
    }

    private fun openSession(): String? = transact(
        SERVICE_PATH, IFACE_SERVICE, "OpenSession",
        buildArgs = { call, iter ->
            bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, "plain")
            bindings.appendVariantString(call, iter, "")
        },
        readReply = { call, rIter, has ->
            if (!has) {
                null
            } else {
                bindings.next(rIter)
                bindings.readText(call, rIter)
            }
        },
    )

    private fun readAliasDefault(): String? = transact(
        SERVICE_PATH, IFACE_SERVICE, "ReadAlias",
        buildArgs = { call, iter -> bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, "default") },
        readReply = { call, rIter, has -> if (!has) null else bindings.readText(call, rIter) },
    )

    private fun serviceUnlock(paths: List<String>): String? = transact(
        SERVICE_PATH, IFACE_SERVICE, "Unlock",
        buildArgs = { call, iter -> bindings.appendObjectPaths(call, iter, paths) },
        readReply = { call, rIter, has ->
            if (!has) {
                null
            } else {
                bindings.next(rIter)
                bindings.readText(call, rIter)
            }
        },
    )

    private fun lockImpl(paths: List<String>): String? = transact(
        SERVICE_PATH, IFACE_SERVICE, "Lock",
        buildArgs = { call, iter -> bindings.appendObjectPaths(call, iter, paths) },
        readReply = { call, rIter, has ->
            if (!has) {
                null
            } else {
                bindings.next(rIter)
                bindings.readText(call, rIter)
            }
        },
    )

    private fun searchItems(attrs: List<Pair<String, String>>): Pair<List<String>, List<String>>? = transact(
        SERVICE_PATH, IFACE_SERVICE, "SearchItems",
        buildArgs = { call, iter -> bindings.appendAttributes(call, iter, attrs) },
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

    private fun getSecret(itemPath: String): ByteArray? = transact(
        itemPath, IFACE_ITEM, "GetSecret",
        buildArgs = { call, iter -> bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_OBJECT_PATH, session) },
        readReply = { call, rIter, has -> if (!has) null else bindings.readSecretValue(call, rIter) },
    )

    private fun createItem(
        collection: String,
        label: String,
        attrs: List<Pair<String, String>>,
        secret: ByteArray,
    ): Pair<String, String>? = transact(
        collection, IFACE_COLLECTION, "CreateItem",
        buildArgs = { call, iter ->
            bindings.appendItemProperties(call, iter, LABEL_PROP, label, ATTRS_PROP, attrs)
            bindings.appendSecret(call, iter, session, secret, CONTENT_TYPE)
            bindings.appendBool(call, iter, true)
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

    private fun deleteItem(itemPath: String): String? = transact(
        itemPath, IFACE_ITEM, "Delete",
        buildArgs = { _, _ -> },
        readReply = { call, rIter, has -> if (!has) null else bindings.readText(call, rIter) },
    )

    private fun closeSession() {
        if (session == NO_OBJECT) return
        transact<Unit>(session, IFACE_SESSION, "Close", buildArgs = { _, _ -> }, readReply = { _, _, _ -> Unit })
    }

    private fun addMatch(rule: String) {
        val c = conn ?: return
        Arena.ofConfined().use { call ->
            val error = call.allocate(bindings.errorLayout)
            bindings.handle("dbus_error_init").invokeExact(error) as Unit
            runCatching { bindings.handle("dbus_bus_add_match").invokeExact(c, call.allocateUtf8(rule), error) as Unit }
            freeErrorIfSet(error)
        }
    }

    // ── org.freedesktop.DBus.Properties.Get readers ──────────────────────────

    private fun getStringProperty(path: String, iface: String, name: String): String? =
        getProperty(path, iface, name) { call, inner -> bindings.readText(call, inner) }

    private fun getUInt64Property(path: String, iface: String, name: String): Long? =
        getProperty(path, iface, name) { call, inner -> bindings.readUInt64(call, inner) }

    private fun getAttributesProperty(path: String): Map<String, String>? =
        getProperty(path, IFACE_ITEM, "Attributes") { call, inner -> bindings.readAttributes(call, inner) }

    private fun getObjectPathsProperty(path: String, iface: String, name: String): List<String>? =
        getProperty(path, iface, name) { call, inner -> bindings.readObjectPaths(call, inner) }

    private fun getBoolProperty(path: String, iface: String, name: String): Boolean? =
        getProperty(path, iface, name) { call, inner ->
            val out = call.allocate(ValueLayout.JAVA_INT)
            bindings.handle("dbus_message_iter_get_basic").invokeExact(inner, out) as Unit
            out.get(ValueLayout.JAVA_INT, 0) != 0
        }

    private fun <T> getProperty(path: String, iface: String, name: String, read: (Arena, MemorySegment) -> T?): T? = transact(
        path, IFACE_PROPERTIES, "Get",
        buildArgs = { call, iter ->
            bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, iface)
            bindings.appendText(call, iter, DBusBindings.DBUS_TYPE_STRING, name)
        },
        readReply = { call, rIter, has ->
            if (!has || bindings.argType(rIter) != DBusBindings.DBUS_TYPE_VARIANT) {
                null
            } else {
                val inner = bindings.scratchIter(call)
                bindings.recurse(rIter, inner)
                read(call, inner)
            }
        },
    )

    private fun freeErrorIfSet(error: MemorySegment) {
        if ((bindings.handle("dbus_error_is_set").invokeExact(error) as Int) != 0) {
            runCatching { bindings.handle("dbus_error_free").invokeExact(error) as Unit }
        }
    }

    /** One blocking D-Bus method call against [SERVICE_NAME]. Null on any failure. */
    private fun <T> transact(
        path: String,
        iface: String,
        member: String,
        buildArgs: (Arena, MemorySegment) -> Unit,
        readReply: (Arena, MemorySegment, Boolean) -> T?,
    ): T? {
        val c = conn ?: return null
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
                    .invokeExact(c, msg, replyTimeoutMs, error) as MemorySegment
                if (reply.address() == 0L) {
                    freeErrorIfSet(error)
                    return null
                }
                try {
                    val rIter = bindings.scratchIter(call)
                    val hasArgs = (bindings.handle("dbus_message_iter_init").invokeExact(reply, rIter) as Int) != 0
                    return readReply(call, rIter, hasArgs)
                } finally {
                    runCatching { bindings.handle("dbus_message_unref").invokeExact(reply) as Unit }
                }
            } finally {
                runCatching { bindings.handle("dbus_message_unref").invokeExact(msg) as Unit }
            }
        }
    }

    companion object {
        private val log: Logger = LoggerFactory.getLogger(SecretServiceVault::class.java)

        private const val SERVICE_NAME = "org.freedesktop.secrets"
        private const val SERVICE_PATH = "/org/freedesktop/secrets"
        private const val IFACE_SERVICE = "org.freedesktop.Secret.Service"
        private const val IFACE_COLLECTION = "org.freedesktop.Secret.Collection"
        private const val IFACE_ITEM = "org.freedesktop.Secret.Item"
        private const val IFACE_SESSION = "org.freedesktop.Secret.Session"
        private const val IFACE_PROMPT = "org.freedesktop.Secret.Prompt"
        private const val IFACE_PROPERTIES = "org.freedesktop.DBus.Properties"
        private const val LABEL_PROP = "org.freedesktop.Secret.Item.Label"
        private const val ATTRS_PROP = "org.freedesktop.Secret.Item.Attributes"
        private const val COLLECTION_LABEL_PROP = "org.freedesktop.Secret.Collection.Label"
        private const val ATTR_APP = "app"
        private const val ATTR_KEY = "key"
        private const val CONTENT_TYPE = "application/octet-stream"
        private const val NO_OBJECT = "/"

        fun create(config: VaultConfig): ProbeResult {
            val replyTimeout = config.opTimeoutMs.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
            val unlockTimeout = config.unlockTimeoutMs.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
            val bindings = DBusBindings.load() ?: return ProbeResult.Unavailable(VaultAvailability.LibraryUnavailable)

            val vault = SecretServiceVault(
                bindings, config.namespace, config.collection, replyTimeout, unlockTimeout, config.unlockPolicy,
            )
            val budget = if (config.unlockPolicy == UnlockPolicy.IfLocked) {
                config.probeTimeoutMs + config.unlockTimeoutMs
            } else {
                config.probeTimeoutMs
            }
            val availability = runCatching {
                vault.setupResult.get(budget, TimeUnit.MILLISECONDS)
            }.getOrElse {
                vault.open.set(false)
                VaultAvailability.ServiceUnavailable
            }
            return if (availability == VaultAvailability.Available) {
                ProbeResult.Opened(vault)
            } else {
                ProbeResult.Unavailable(availability)
            }
        }
    }
}
