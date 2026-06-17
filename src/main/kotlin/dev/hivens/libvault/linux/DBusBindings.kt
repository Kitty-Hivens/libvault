package dev.hivens.libvault.linux

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle

/**
 * Panama bindings to `libdbus-1` -- the reference D-Bus client shipped on every
 * desktop Linux. Loaded once via [load]; the result holds the client-subset
 * handles the Secret Service backend uses. No dbus-java, no runtime libsecret,
 * no GLib: just the wire protocol over libdbus, the same approach libtray and
 * libnotify take.
 *
 * Constant values and struct shapes track `dbus/dbus.h` upstream.
 */
internal class DBusBindings private constructor(
    val arena: Arena,
    private val handles: Map<String, MethodHandle>,
) {
    fun handle(name: String): MethodHandle =
        handles[name] ?: error("DBus handle not loaded: $name. Add it to LOAD_SET in DBusBindings.load.")

    companion object {
        /** Bus types from dbus/dbus-shared.h. */
        const val DBUS_BUS_SESSION: Int = 0

        /** Message type from dbus/dbus-protocol.h. */
        const val DBUS_MESSAGE_TYPE_SIGNAL: Int = 4

        /** Type signatures from dbus/dbus-protocol.h. Single-byte ASCII. */
        const val DBUS_TYPE_INVALID: Byte = 0
        const val DBUS_TYPE_BYTE: Byte = 'y'.code.toByte()
        const val DBUS_TYPE_BOOLEAN: Byte = 'b'.code.toByte()
        const val DBUS_TYPE_UINT64: Byte = 't'.code.toByte()
        const val DBUS_TYPE_STRING: Byte = 's'.code.toByte()
        const val DBUS_TYPE_OBJECT_PATH: Byte = 'o'.code.toByte()
        const val DBUS_TYPE_ARRAY: Byte = 'a'.code.toByte()
        const val DBUS_TYPE_VARIANT: Byte = 'v'.code.toByte()
        const val DBUS_TYPE_STRUCT: Byte = 'r'.code.toByte()  // also '(' ')'
        const val DBUS_TYPE_DICT_ENTRY: Byte = 'e'.code.toByte()  // also '{' '}'

        private val LIB_CANDIDATES = listOf("dbus-1", "dbus-1.so.3", "libdbus-1.so.3")

        private val LOAD_SET: List<Triple<String, MemoryLayout?, List<MemoryLayout>>> = listOf(
            // Connection lifecycle
            Triple("dbus_bus_get", ValueLayout.ADDRESS, listOf(ValueLayout.JAVA_INT, ValueLayout.ADDRESS)),
            Triple("dbus_connection_unref", null, listOf(ValueLayout.ADDRESS)),
            // exit_on_disconnect defaults TRUE on the shared bus connection --
            // a bus restart would call _exit(). We turn it off; a credentials
            // library must not take the host process down with the session bus.
            Triple("dbus_connection_set_exit_on_disconnect", null, listOf(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)),
            Triple("dbus_connection_flush", null, listOf(ValueLayout.ADDRESS)),
            Triple(
                "dbus_connection_send_with_reply_and_block",
                ValueLayout.ADDRESS,
                listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
            ),
            // Signal subscription + non-blocking receive (watch + unlock pump)
            Triple("dbus_bus_add_match", null, listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS)),
            Triple("dbus_connection_read_write", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS, ValueLayout.JAVA_INT)),
            Triple("dbus_connection_pop_message", ValueLayout.ADDRESS, listOf(ValueLayout.ADDRESS)),

            // Message construction / teardown / inspection
            Triple(
                "dbus_message_new_method_call",
                ValueLayout.ADDRESS,
                listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            ),
            Triple("dbus_message_unref", null, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_message_get_type", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_message_get_member", ValueLayout.ADDRESS, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_message_get_interface", ValueLayout.ADDRESS, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_message_get_path", ValueLayout.ADDRESS, listOf(ValueLayout.ADDRESS)),

            // Iterator API
            Triple("dbus_message_iter_init", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS)),
            Triple("dbus_message_iter_init_append", null, listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS)),
            Triple(
                "dbus_message_iter_append_basic",
                ValueLayout.JAVA_INT,
                listOf(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
            ),
            Triple(
                "dbus_message_iter_open_container",
                ValueLayout.JAVA_INT,
                listOf(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            ),
            Triple("dbus_message_iter_close_container", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS)),
            Triple("dbus_message_iter_recurse", null, listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS)),
            Triple("dbus_message_iter_next", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_message_iter_get_arg_type", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_message_iter_get_basic", null, listOf(ValueLayout.ADDRESS, ValueLayout.ADDRESS)),

            // Error API
            Triple("dbus_error_init", null, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_error_is_set", ValueLayout.JAVA_INT, listOf(ValueLayout.ADDRESS)),
            Triple("dbus_error_free", null, listOf(ValueLayout.ADDRESS)),
        )

        /**
         * Load libdbus and bind every symbol in [LOAD_SET]. Returns null when
         * the library is absent or any symbol is missing -- the Linux backend
         * then reports unavailable and selection degrades to the file fallback.
         */
        fun load(): DBusBindings? {
            val arena = Arena.ofShared()
            val lookup = LIB_CANDIDATES.firstNotNullOfOrNull { name ->
                runCatching { SymbolLookup.libraryLookup(name, arena) }.getOrNull()
            } ?: run {
                arena.close()
                return null
            }
            val linker = Linker.nativeLinker()
            val handles = HashMap<String, MethodHandle>(LOAD_SET.size * 2)
            for ((name, ret, args) in LOAD_SET) {
                val descriptor = if (ret == null) {
                    FunctionDescriptor.ofVoid(*args.toTypedArray())
                } else {
                    FunctionDescriptor.of(ret, *args.toTypedArray())
                }
                val symbol = lookup.find(name).orElse(null) ?: run {
                    arena.close()
                    return null
                }
                handles[name] = linker.downcallHandle(symbol, descriptor)
            }
            return DBusBindings(arena, handles)
        }
    }

    /** `DBusError` -- allocate-and-forget; we never read fields, only is_set. 32 bytes. */
    val errorLayout: MemoryLayout = MemoryLayout.structLayout(
        ValueLayout.ADDRESS.withName("name"),
        ValueLayout.ADDRESS.withName("message"),
        ValueLayout.JAVA_INT.withName("flags"),
        MemoryLayout.paddingLayout(4),
        ValueLayout.ADDRESS.withName("padding1"),
    )

    /**
     * `DBusMessageIter` -- a stack cursor libdbus declares "small" but never
     * sizes in the public ABI. Real struct is 72 bytes on x86_64 / aarch64; a
     * 64-byte buffer let libdbus write 8 bytes past it on every iter call.
     * Reserve 80.
     *
     * Backed by JAVA_LONG, not JAVA_BYTE: the struct holds pointers and must be
     * 8-byte aligned. A `sequenceLayout(80, JAVA_BYTE)` has byteAlignment() == 1,
     * so `Arena.allocate` would only guarantee 1-byte alignment -- it happens to
     * survive on x86_64 glibc (malloc returns 16-byte-aligned) but is undefined
     * on strict-alignment aarch64. 10 longs = 80 bytes, alignment 8.
     */
    val messageIterLayout: MemoryLayout = MemoryLayout.sequenceLayout(10, ValueLayout.JAVA_LONG)
}

/** Allocate a UTF-8 NUL-terminated string in this arena. */
internal fun Arena.allocateUtf8(s: String): MemorySegment {
    val bytes = s.toByteArray(Charsets.UTF_8)
    val segment = allocate((bytes.size + 1).toLong())
    if (bytes.isNotEmpty()) {
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.size)
    }
    segment.set(ValueLayout.JAVA_BYTE, bytes.size.toLong(), 0)
    return segment
}
