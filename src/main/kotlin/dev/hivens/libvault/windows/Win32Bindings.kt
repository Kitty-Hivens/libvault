package dev.hivens.libvault.windows

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.charset.StandardCharsets

/**
 * Panama bindings to `Advapi32.dll`'s Credential Manager API plus the raw
 * store/retrieve/delete/enumerate/describe marshalling. Stateless apart from the
 * handles and the arena that keeps the library loaded.
 *
 * advapi32 surface:
 * ```c
 * BOOL CredWriteW    (PCREDENTIALW Credential, DWORD Flags);
 * BOOL CredReadW     (LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW *Credential);
 * BOOL CredDeleteW   (LPCWSTR TargetName, DWORD Type, DWORD Flags);
 * BOOL CredEnumerateW(LPCWSTR Filter, DWORD Flags, DWORD *Count, PCREDENTIALW **Credentials);
 * void CredFree      (PVOID Buffer);
 * ```
 */
internal class Win32Bindings private constructor(
    private val arena: Arena,
    private val credWrite: MethodHandle,
    private val credRead: MethodHandle,
    private val credDelete: MethodHandle,
    private val credEnumerate: MethodHandle,
    private val credFree: MethodHandle,
) {

    /** Metadata read alongside a credential: its comment (label) and last-written time. */
    class Meta(val comment: String?, val lastWrittenMillis: Long)

    fun write(target: String, secret: ByteArray, comment: String?): Boolean = Arena.ofConfined().use { call ->
        runCatching {
            val targetSeg = call.allocateUtf16LE(target)
            val commentSeg = comment?.let { call.allocateUtf16LE(it) } ?: MemorySegment.NULL
            val userName = call.allocateUtf16LE("")
            val secretSeg = call.allocate(secret.size.toLong().coerceAtLeast(1))
            if (secret.isNotEmpty()) {
                MemorySegment.copy(secret, 0, secretSeg, ValueLayout.JAVA_BYTE, 0, secret.size)
            }

            val cred = call.allocate(CREDENTIAL_LAYOUT)
            cred.set(ValueLayout.JAVA_INT, 0, FLAGS_NONE)
            cred.set(ValueLayout.JAVA_INT, 4, CRED_TYPE_GENERIC)
            cred.set(ValueLayout.ADDRESS, 8, targetSeg)
            cred.set(ValueLayout.ADDRESS, 16, commentSeg)
            cred.set(ValueLayout.JAVA_INT, 24, 0)
            cred.set(ValueLayout.JAVA_INT, 28, 0)
            cred.set(ValueLayout.JAVA_INT, 32, secret.size)
            cred.set(ValueLayout.ADDRESS, 40, secretSeg)
            cred.set(ValueLayout.JAVA_INT, 48, CRED_PERSIST_LOCAL_MACHINE)
            cred.set(ValueLayout.JAVA_INT, 52, 0)
            cred.set(ValueLayout.ADDRESS, 56, MemorySegment.NULL)
            cred.set(ValueLayout.ADDRESS, 64, MemorySegment.NULL)
            cred.set(ValueLayout.ADDRESS, 72, userName)

            (credWrite.invokeExact(cred, FLAGS_NONE) as Int) != 0
        }.getOrDefault(false)
    }

    fun read(target: String): ByteArray? = withCredential(target) { cred ->
        val blobSize = cred.get(ValueLayout.JAVA_INT, 32)
        val blobPtr = cred.get(ValueLayout.ADDRESS, 40)
        if (blobSize > 0 && blobPtr.address() != 0L) {
            blobPtr.reinterpret(blobSize.toLong()).toArray(ValueLayout.JAVA_BYTE)
        } else {
            ByteArray(0)
        }
    }

    fun readMeta(target: String): Meta? = withCredential(target) { cred ->
        val commentPtr = cred.get(ValueLayout.ADDRESS, 16)
        val comment = if (commentPtr.address() != 0L) readUtf16(commentPtr) else null
        val low = cred.get(ValueLayout.JAVA_INT, 24).toLong() and 0xFFFFFFFFL
        val high = cred.get(ValueLayout.JAVA_INT, 28).toLong() and 0xFFFFFFFFL
        Meta(comment, fileTimeToMillis((high shl 32) or low))
    }

    fun delete(target: String): Boolean = Arena.ofConfined().use { call ->
        runCatching {
            val targetSeg = call.allocateUtf16LE(target)
            (credDelete.invokeExact(targetSeg, CRED_TYPE_GENERIC, FLAGS_NONE) as Int) != 0
        }.getOrDefault(false)
    }

    /** Full target names matching the wildcard [filter] (e.g. the namespace prefix). Empty on fault. */
    fun enumerate(filter: String): List<String> = Arena.ofConfined().use { call ->
        runCatching {
            val filterSeg = call.allocateUtf16LE(filter)
            val countOut = call.allocate(ValueLayout.JAVA_INT)
            val arrOut = call.allocate(ValueLayout.ADDRESS)
            val ok = credEnumerate.invokeExact(filterSeg, FLAGS_NONE, countOut, arrOut) as Int
            if (ok == 0) return@use emptyList<String>()
            val count = countOut.get(ValueLayout.JAVA_INT, 0)
            val arrPtr = arrOut.get(ValueLayout.ADDRESS, 0)
            if (count <= 0 || arrPtr.address() == 0L) return@use emptyList<String>()
            val array = arrPtr.reinterpret((count.toLong()) * ValueLayout.ADDRESS.byteSize())
            try {
                val out = ArrayList<String>(count)
                for (i in 0 until count) {
                    val credPtr = array.getAtIndex(ValueLayout.ADDRESS, i.toLong())
                    if (credPtr.address() == 0L) continue
                    val cred = credPtr.reinterpret(CREDENTIAL_LAYOUT.byteSize())
                    val targetPtr = cred.get(ValueLayout.ADDRESS, 8)
                    if (targetPtr.address() != 0L) out += readUtf16(targetPtr)
                }
                out
            } finally {
                credFree.invokeExact(arrPtr) as Unit
            }
        }.getOrDefault(emptyList())
    }

    fun close() {
        runCatching { arena.close() }
    }

    private fun <T> withCredential(target: String, read: (MemorySegment) -> T): T? = Arena.ofConfined().use { call ->
        runCatching {
            val targetSeg = call.allocateUtf16LE(target)
            val outPtr = call.allocate(ValueLayout.ADDRESS)
            val result = credRead.invokeExact(targetSeg, CRED_TYPE_GENERIC, FLAGS_NONE, outPtr) as Int
            if (result == 0) return@use null
            val credAddress = outPtr.get(ValueLayout.ADDRESS, 0)
            if (credAddress.address() == 0L) return@use null
            try {
                read(credAddress.reinterpret(CREDENTIAL_LAYOUT.byteSize()))
            } finally {
                credFree.invokeExact(credAddress) as Unit
            }
        }.getOrNull()
    }

    private fun readUtf16(ptr: MemorySegment): String =
        ptr.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_16LE)

    private fun fileTimeToMillis(fileTime: Long): Long =
        if (fileTime <= 0) 0 else fileTime / 10_000L - 11_644_473_600_000L

    companion object {
        private const val CRED_TYPE_GENERIC = 1
        private const val CRED_PERSIST_LOCAL_MACHINE = 2
        private const val FLAGS_NONE = 0
        private const val ADVAPI32 = "Advapi32"

        private val CREDENTIAL_LAYOUT: MemoryLayout = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("Flags"),
            ValueLayout.JAVA_INT.withName("Type"),
            ValueLayout.ADDRESS.withName("TargetName"),
            ValueLayout.ADDRESS.withName("Comment"),
            ValueLayout.JAVA_INT.withName("LastWritten_Low"),
            ValueLayout.JAVA_INT.withName("LastWritten_High"),
            ValueLayout.JAVA_INT.withName("CredentialBlobSize"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("CredentialBlob"),
            ValueLayout.JAVA_INT.withName("Persist"),
            ValueLayout.JAVA_INT.withName("AttributeCount"),
            ValueLayout.ADDRESS.withName("Attributes"),
            ValueLayout.ADDRESS.withName("TargetAlias"),
            ValueLayout.ADDRESS.withName("UserName"),
        )

        fun load(): Win32Bindings? {
            val arena = Arena.ofShared()
            val lookup = runCatching { SymbolLookup.libraryLookup(ADVAPI32, arena) }.getOrNull()
                ?: run { arena.close(); return null }
            val credWrite = lookup.downcall(
                "CredWriteW",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
            )
            val credRead = lookup.downcall(
                "CredReadW",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                ),
            )
            val credDelete = lookup.downcall(
                "CredDeleteW",
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
            )
            val credEnumerate = lookup.downcall(
                "CredEnumerateW",
                FunctionDescriptor.of(
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                ),
            )
            val credFree = lookup.downcall("CredFree", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))
            if (credWrite == null || credRead == null || credDelete == null || credEnumerate == null || credFree == null) {
                arena.close()
                return null
            }
            return Win32Bindings(arena, credWrite, credRead, credDelete, credEnumerate, credFree)
        }
    }
}

private fun Arena.allocateUtf16LE(s: String): MemorySegment {
    val bytes = s.toByteArray(Charsets.UTF_16LE)
    val segment = allocate((bytes.size + 2).toLong())
    MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.size)
    segment.set(ValueLayout.JAVA_BYTE, bytes.size.toLong(), 0)
    segment.set(ValueLayout.JAVA_BYTE, (bytes.size + 1).toLong(), 0)
    return segment
}

private fun SymbolLookup.downcall(name: String, descriptor: FunctionDescriptor): MethodHandle? {
    val symbol = find(name).orElse(null) ?: return null
    return Linker.nativeLinker().downcallHandle(symbol, descriptor)
}
