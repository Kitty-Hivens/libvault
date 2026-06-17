package dev.hivens.libvault.linux

import java.io.ByteArrayOutputStream
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

internal fun DBusBindings.scratchIter(call: Arena): MemorySegment = call.allocate(messageIterLayout)

internal fun DBusBindings.argType(iter: MemorySegment): Byte =
    (handle("dbus_message_iter_get_arg_type").invokeExact(iter) as Int).toByte()

internal fun DBusBindings.next(iter: MemorySegment): Boolean =
    (handle("dbus_message_iter_next").invokeExact(iter) as Int) != 0

internal fun DBusBindings.recurse(parent: MemorySegment, sub: MemorySegment) {
    handle("dbus_message_iter_recurse").invokeExact(parent, sub) as Unit
}

internal fun DBusBindings.openContainer(parent: MemorySegment, type: Byte, signature: MemorySegment, sub: MemorySegment) {
    handle("dbus_message_iter_open_container").invokeExact(parent, type.toInt(), signature, sub) as Int
}

internal fun DBusBindings.closeContainer(parent: MemorySegment, sub: MemorySegment) {
    handle("dbus_message_iter_close_container").invokeExact(parent, sub) as Int
}

// ── Basic appends ────────────────────────────────────────────────────────────

/** Append a string- or object-path-typed basic value (pass the matching type byte). */
internal fun DBusBindings.appendText(call: Arena, iter: MemorySegment, type: Byte, value: String) {
    val strSeg = call.allocateUtf8(value)
    val ptrBuf = call.allocate(LAYOUT_ADDR)
    ptrBuf.set(LAYOUT_ADDR, 0, strSeg)
    handle("dbus_message_iter_append_basic").invokeExact(iter, type.toInt(), ptrBuf) as Int
}

internal fun DBusBindings.appendBool(call: Arena, iter: MemorySegment, value: Boolean) {
    // dbus_bool_t is 4 bytes on the wire, not 1.
    val buf = call.allocate(ValueLayout.JAVA_INT)
    buf.set(ValueLayout.JAVA_INT, 0, if (value) 1 else 0)
    handle("dbus_message_iter_append_basic").invokeExact(iter, DBusBindings.DBUS_TYPE_BOOLEAN.toInt(), buf) as Int
}

internal fun DBusBindings.appendByteArray(call: Arena, iter: MemorySegment, bytes: ByteArray) {
    val sig = call.allocateUtf8("y")
    val array = scratchIter(call)
    openContainer(iter, DBusBindings.DBUS_TYPE_ARRAY, sig, array)
    val byteBuf = call.allocate(LAYOUT_BYTE)
    for (b in bytes) {
        byteBuf.set(LAYOUT_BYTE, 0, b)
        handle("dbus_message_iter_append_basic").invokeExact(array, DBusBindings.DBUS_TYPE_BYTE.toInt(), byteBuf) as Int
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
    val buffer = ByteArrayOutputStream()
    val byteOut = call.allocate(LAYOUT_BYTE)
    while (argType(sub) == DBusBindings.DBUS_TYPE_BYTE) {
        handle("dbus_message_iter_get_basic").invokeExact(sub, byteOut) as Unit
        buffer.write(byteOut.get(LAYOUT_BYTE, 0).toInt())
        next(sub)
    }
    return buffer.toByteArray()
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
