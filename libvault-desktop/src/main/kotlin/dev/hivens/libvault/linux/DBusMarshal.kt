package dev.hivens.libvault.linux

import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout

/**
 * D-Bus argument marshalling for the Secret Service shapes, on top of
 * [DBusBindings]. Mirrors libnotify's DBusMarshal but carries the extra
 * container types Secret Service needs: `a{ss}` attribute maps, `a{sv}` item
 * properties, the `(oayays)` Secret struct, `ao` object-path arrays, and `ay`
 * byte arrays.
 *
 * Every scratch allocation comes from the caller's `call` arena; nothing here
 * outlives a single method call.
 */

private val LAYOUT_BYTE = ValueLayout.JAVA_BYTE
private val LAYOUT_ADDR = ValueLayout.ADDRESS

/**
 * libdbus append/container calls return `dbus_bool_t`; FALSE means out of
 * memory, after which the message is half-built and further iter calls are
 * undefined. Throw instead of continuing -- [SecretServiceVault]'s `transact`
 * runs inside the bounded executor, so the throw degrades the op to false/null.
 */
private fun dbusOk(result: Int, op: String) {
    if (result == 0) throw IllegalStateException("libdbus $op returned FALSE (out of memory)")
}

internal fun DBusBindings.scratchIter(call: Arena): MemorySegment = call.allocate(messageIterLayout)

internal fun DBusBindings.argType(iter: MemorySegment): Byte =
    (handle("dbus_message_iter_get_arg_type").invokeExact(iter) as Int).toByte()

internal fun DBusBindings.next(iter: MemorySegment): Boolean =
    (handle("dbus_message_iter_next").invokeExact(iter) as Int) != 0

internal fun DBusBindings.recurse(parent: MemorySegment, sub: MemorySegment) {
    handle("dbus_message_iter_recurse").invokeExact(parent, sub) as Unit
}

internal fun DBusBindings.openContainer(parent: MemorySegment, type: Byte, signature: MemorySegment, sub: MemorySegment) {
    dbusOk(handle("dbus_message_iter_open_container").invokeExact(parent, type.toInt(), signature, sub) as Int, "open_container")
}

internal fun DBusBindings.closeContainer(parent: MemorySegment, sub: MemorySegment) {
    dbusOk(handle("dbus_message_iter_close_container").invokeExact(parent, sub) as Int, "close_container")
}

// ── Basic appends ────────────────────────────────────────────────────────────

/** Append a string- or object-path-typed basic value (pass the matching type byte). */
internal fun DBusBindings.appendText(call: Arena, iter: MemorySegment, type: Byte, value: String) {
    val strSeg = call.allocateUtf8(value)
    val ptrBuf = call.allocate(LAYOUT_ADDR)
    ptrBuf.set(LAYOUT_ADDR, 0, strSeg)
    dbusOk(handle("dbus_message_iter_append_basic").invokeExact(iter, type.toInt(), ptrBuf) as Int, "append_basic")
}

internal fun DBusBindings.appendBool(call: Arena, iter: MemorySegment, value: Boolean) {
    // dbus_bool_t is 4 bytes on the wire, not 1.
    val buf = call.allocate(ValueLayout.JAVA_INT)
    buf.set(ValueLayout.JAVA_INT, 0, if (value) 1 else 0)
    dbusOk(handle("dbus_message_iter_append_basic").invokeExact(iter, DBusBindings.DBUS_TYPE_BOOLEAN.toInt(), buf) as Int, "append_basic")
}

internal fun DBusBindings.appendByteArray(call: Arena, iter: MemorySegment, bytes: ByteArray) {
    val sig = call.allocateUtf8("y")
    val array = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_ARRAY, sig, array)
    if (bytes.isNotEmpty()) {
        val data = call.allocate(bytes.size.toLong())
        try {
            MemorySegment.copy(bytes, 0, data, LAYOUT_BYTE, 0, bytes.size)
            // append_fixed_array takes the address of the array pointer, not the pointer.
            val dataPtr = call.allocate(LAYOUT_ADDR)
            dataPtr.set(LAYOUT_ADDR, 0, data)
            dbusOk(
                handle("dbus_message_iter_append_fixed_array")
                    .invokeExact(array, DBusBindings.DBUS_TYPE_BYTE.toInt(), dataPtr, bytes.size) as Int,
                "append_fixed_array",
            )
        } finally {
            data.fill(0)
        }
    }
    closeContainer(iter, array)
}

// ── Variants ─────────────────────────────────────────────────────────────────

internal fun DBusBindings.appendVariantString(call: Arena, parent: MemorySegment, value: String) {
    val sig = call.allocateUtf8("s")
    val variant = scratchIter(call)
    openContainer(parent, DBusBindings.DBUS_TYPE_VARIANT, sig, variant)
    appendText(call, variant, DBusBindings.DBUS_TYPE_STRING, value)
    closeContainer(parent, variant)
}

/** Append a variant wrapping an `a{ss}` attribute map. */
internal fun DBusBindings.appendVariantAttributes(call: Arena, parent: MemorySegment, attrs: List<Pair<String, String>>) {
    val variantSig = call.allocateUtf8("a{ss}")
    val variant = scratchIter(call)
    openContainer(parent, DBusBindings.DBUS_TYPE_VARIANT, variantSig, variant)
    appendAttributes(call, variant, attrs)
    closeContainer(parent, variant)
}

// ── Attribute map a{ss} ──────────────────────────────────────────────────────

internal fun DBusBindings.appendAttributes(call: Arena, iter: MemorySegment, attrs: List<Pair<String, String>>) {
    val entrySig = call.allocateUtf8("{ss}")
    val array = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_ARRAY, entrySig, array)
    for ((k, v) in attrs) {
        val entry = scratchIter(call)
        openContainer(array, DBusBindings.DBUS_TYPE_DICT_ENTRY, MemorySegment.NULL, entry)
        appendText(call, entry, DBusBindings.DBUS_TYPE_STRING, k)
        appendText(call, entry, DBusBindings.DBUS_TYPE_STRING, v)
        closeContainer(array, entry)
    }
    closeContainer(iter, array)
}

// ── Item properties a{sv} (Label + Attributes) ───────────────────────────────

internal fun DBusBindings.appendItemProperties(
    call: Arena,
    iter: MemorySegment,
    labelKey: String,
    label: String,
    attrsKey: String,
    attrs: List<Pair<String, String>>,
) {
    val entrySig = call.allocateUtf8("{sv}")
    val array = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_ARRAY, entrySig, array)

    val labelEntry = scratchIter(call)
    openContainer(array, DBusBindings.DBUS_TYPE_DICT_ENTRY, MemorySegment.NULL, labelEntry)
    appendText(call, labelEntry, DBusBindings.DBUS_TYPE_STRING, labelKey)
    appendVariantString(call, labelEntry, label)
    closeContainer(array, labelEntry)

    val attrsEntry = scratchIter(call)
    openContainer(array, DBusBindings.DBUS_TYPE_DICT_ENTRY, MemorySegment.NULL, attrsEntry)
    appendText(call, attrsEntry, DBusBindings.DBUS_TYPE_STRING, attrsKey)
    appendVariantAttributes(call, attrsEntry, attrs)
    closeContainer(array, attrsEntry)

    closeContainer(iter, array)
}

/** Append an `a{sv}` with a single `{ labelKey: variant string }` entry (CreateCollection). */
internal fun DBusBindings.appendCollectionProperties(call: Arena, iter: MemorySegment, labelKey: String, label: String) {
    val entrySig = call.allocateUtf8("{sv}")
    val array = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_ARRAY, entrySig, array)
    val entry = scratchIter(call)
    openContainer(array, DBusBindings.DBUS_TYPE_DICT_ENTRY, MemorySegment.NULL, entry)
    appendText(call, entry, DBusBindings.DBUS_TYPE_STRING, labelKey)
    appendVariantString(call, entry, label)
    closeContainer(array, entry)
    closeContainer(iter, array)
}

// ── Secret struct (oayays) ───────────────────────────────────────────────────

internal fun DBusBindings.appendSecret(
    call: Arena,
    iter: MemorySegment,
    sessionPath: String,
    value: ByteArray,
    contentType: String,
) {
    val struct = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_STRUCT, MemorySegment.NULL, struct)
    appendText(call, struct, DBusBindings.DBUS_TYPE_OBJECT_PATH, sessionPath)
    appendByteArray(call, struct, ByteArray(0)) // parameters: empty for the "plain" algorithm
    appendByteArray(call, struct, value)
    appendText(call, struct, DBusBindings.DBUS_TYPE_STRING, contentType)
    closeContainer(iter, struct)
}

// ── Object-path array ao ─────────────────────────────────────────────────────

internal fun DBusBindings.appendObjectPaths(call: Arena, iter: MemorySegment, paths: List<String>) {
    val sig = call.allocateUtf8("o")
    val array = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_ARRAY, sig, array)
    for (p in paths) appendText(call, array, DBusBindings.DBUS_TYPE_OBJECT_PATH, p)
    closeContainer(iter, array)
}

// ── Reads ────────────────────────────────────────────────────────────────────

internal fun DBusBindings.readText(call: Arena, iter: MemorySegment): String? {
    val type = argType(iter)
    if (type != DBusBindings.DBUS_TYPE_STRING && type != DBusBindings.DBUS_TYPE_OBJECT_PATH) return null
    val out = call.allocate(LAYOUT_ADDR)
    handle("dbus_message_iter_get_basic").invokeExact(iter, out) as Unit
    val ptr = out.get(LAYOUT_ADDR, 0)
    return if (ptr.address() == 0L) null else ptr.reinterpret(Long.MAX_VALUE).getString(0)
}

internal fun DBusBindings.readObjectPaths(call: Arena, iter: MemorySegment): List<String> {
    if (argType(iter) != DBusBindings.DBUS_TYPE_ARRAY) return emptyList()
    val sub = scratchIter(call)
    recurse(iter, sub)
    val out = ArrayList<String>()
    while (argType(sub) != DBusBindings.DBUS_TYPE_INVALID) {
        readText(call, sub)?.let { out += it }
        next(sub)
    }
    return out
}

internal fun DBusBindings.readByteArray(call: Arena, iter: MemorySegment): ByteArray? {
    if (argType(iter) != DBusBindings.DBUS_TYPE_ARRAY) return null
    val sub = scratchIter(call)
    recurse(iter, sub)
    if (argType(sub) != DBusBindings.DBUS_TYPE_BYTE) return ByteArray(0)
    val dataOut = call.allocate(LAYOUT_ADDR)
    val countOut = call.allocate(ValueLayout.JAVA_INT)
    handle("dbus_message_iter_get_fixed_array").invokeExact(sub, dataOut, countOut) as Unit
    val count = countOut.get(ValueLayout.JAVA_INT, 0)
    val data = dataOut.get(LAYOUT_ADDR, 0)
    // The block points into the reply message, which the caller unrefs. It is
    // copied out once, straight into the array the caller receives.
    return if (count <= 0 || data.address() == 0L) ByteArray(0) else data.reinterpret(count.toLong()).toArray(LAYOUT_BYTE)
}

/** Read the `value` field (3rd) out of a `(oayays)` Secret struct at [iter]. */
internal fun DBusBindings.readSecretValue(call: Arena, iter: MemorySegment): ByteArray? {
    if (argType(iter) != DBusBindings.DBUS_TYPE_STRUCT) return null
    val struct = scratchIter(call)
    recurse(iter, struct)
    next(struct) // session (o) -> parameters (ay)
    next(struct) // parameters (ay) -> value (ay)
    return readByteArray(call, struct)
}

/** Read a uint64 (`t`, e.g. a Created/Modified timestamp), or null if not one. */
internal fun DBusBindings.readUInt64(call: Arena, iter: MemorySegment): Long? {
    if (argType(iter) != DBusBindings.DBUS_TYPE_UINT64) return null
    val out = call.allocate(ValueLayout.JAVA_LONG)
    handle("dbus_message_iter_get_basic").invokeExact(iter, out) as Unit
    return out.get(ValueLayout.JAVA_LONG, 0)
}

/** Read an `a{ss}` map (e.g. item Attributes) at the iterator's cursor. */
internal fun DBusBindings.readAttributes(call: Arena, iter: MemorySegment): Map<String, String> {
    if (argType(iter) != DBusBindings.DBUS_TYPE_ARRAY) return emptyMap()
    val array = scratchIter(call)
    recurse(iter, array)
    val out = LinkedHashMap<String, String>()
    while (argType(array) == DBusBindings.DBUS_TYPE_DICT_ENTRY) {
        val entry = scratchIter(call)
        recurse(array, entry)
        val k = readText(call, entry)
        next(entry)
        val v = readText(call, entry)
        if (k != null && v != null) out[k] = v
        next(array)
    }
    return out
}

/** Read the result of a message accessor returning a `const char *` (member/interface/path). */
internal fun DBusBindings.readMessageString(symbol: String, msg: MemorySegment): String? {
    val ptr = handle(symbol).invokeExact(msg) as MemorySegment
    return if (ptr.address() == 0L) null else ptr.reinterpret(Long.MAX_VALUE).getString(0)
}
