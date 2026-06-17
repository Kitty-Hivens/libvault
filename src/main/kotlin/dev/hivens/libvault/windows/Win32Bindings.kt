package dev.hivens.libvault.windows

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle

/**
 * Panama bindings to `Advapi32.dll`'s Credential Manager API, plus the raw
 * store/retrieve/delete/exists marshalling. Stateless apart from the handles and
 * the arena that keeps the library loaded; the vault is a thin wrapper.
 *
 * Each entry is encrypted by Windows via DPAPI -- machine-and-user bound, so a
 * copied blob is useless on another machine. `TargetName` carries the
 * `namespace/key` tuple (the same convention Git Credential Manager uses).
 *
 * advapi32 surface:
 * ```c
 * BOOL CredWriteW (PCREDENTIALW Credential, DWORD Flags);
 * BOOL CredReadW  (LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW *Credential);
 * BOOL CredDeleteW(LPCWSTR TargetName, DWORD Type, DWORD Flags);
 * void CredFree   (PVOID Buffer);
 * ```
 */
internal class Win32Bindings private constructor(
    private val arena: Arena,
    private val credWrite: MethodHandle,
    private val credRead: MethodHandle,
    private val credDelete: MethodHandle,
    private val credFree: MethodHandle,
) {

    fun write(target: String, secret: ByteArray): Boolean = Arena.ofConfined().use { call ->
        runCatching {
            val targetSeg = call.allocateUtf16LE(target)
            val userName = call.allocateUtf16LE("")
            val secretSeg = call.allocate(secret.size.toLong().coerceAtLeast(1))
            if (secret.isNotEmpty()) {
                MemorySegment.copy(secret, 0, secretSeg, ValueLayout.JAVA_BYTE, 0, secret.size)
            }

            val cred = call.allocate(CREDENTIAL_LAYOUT)
            cred.set(ValueLayout.JAVA_INT, 0, FLAGS_NONE)
            cred.set(ValueLayout.JAVA_INT, 4, CRED_TYPE_GENERIC)
            cred.set(ValueLayout.ADDRESS, 8, targetSeg)
            cred.set(ValueLayout.ADDRESS, 16, MemorySegment.NULL)        // Comment
            cred.set(ValueLayout.JAVA_INT, 24, 0)                        // LastWritten.Low
            cred.set(ValueLayout.JAVA_INT, 28, 0)                        // LastWritten.High
            cred.set(ValueLayout.JAVA_INT, 32, secret.size)             // CredentialBlobSize
            cred.set(ValueLayout.ADDRESS, 40, secretSeg)                 // CredentialBlob
            cred.set(ValueLayout.JAVA_INT, 48, CRED_PERSIST_LOCAL_MACHINE)
            cred.set(ValueLayout.JAVA_INT, 52, 0)                        // AttributeCount
            cred.set(ValueLayout.ADDRESS, 56, MemorySegment.NULL)        // Attributes
            cred.set(ValueLayout.ADDRESS, 64, MemorySegment.NULL)        // TargetAlias
            cred.set(ValueLayout.ADDRESS, 72, userName)                  // UserName

            (credWrite.invokeExact(cred, FLAGS_NONE) as Int) != 0
        }.getOrDefault(false)
    }

    fun read(target: String): ByteArray? = Arena.ofConfined().use { call ->
        runCatching {
            val targetSeg = call.allocateUtf16LE(target)
            val outPtr = call.allocate(ValueLayout.ADDRESS)
            val result = credRead.invokeExact(targetSeg, CRED_TYPE_GENERIC, FLAGS_NONE, outPtr) as Int
            if (result == 0) return@use null

            val credAddress = outPtr.get(ValueLayout.ADDRESS, 0)
            if (credAddress.address() == 0L) return@use null

            val cred = credAddress.reinterpret(CREDENTIAL_LAYOUT.byteSize())
            val blobSize = cred.get(ValueLayout.JAVA_INT, 32)
            val blobPtr = cred.get(ValueLayout.ADDRESS, 40)
            val value = if (blobSize > 0 && blobPtr.address() != 0L) {
                blobPtr.reinterpret(blobSize.toLong()).toArray(ValueLayout.JAVA_BYTE)
            } else {
                ByteArray(0)
            }
            credFree.invokeExact(credAddress) as Unit
            value
        }.getOrNull()
    }

    fun delete(target: String): Boolean = Arena.ofConfined().use { call ->
        runCatching {
            val targetSeg = call.allocateUtf16LE(target)
            (credDelete.invokeExact(targetSeg, CRED_TYPE_GENERIC, FLAGS_NONE) as Int) != 0
        }.getOrDefault(false)
    }

    fun close() {
        runCatching { arena.close() }
    }

    companion object {
        private const val CRED_TYPE_GENERIC = 1
        private const val CRED_PERSIST_LOCAL_MACHINE = 2
        private const val FLAGS_NONE = 0
        private const val ADVAPI32 = "Advapi32"

        // CREDENTIALW layout per wincred.h (x86_64 offsets in the field comments
        // of WindowsCredentialManagerKeyringStorage this was lifted from).
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
            val credFree = lookup.downcall("CredFree", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))
            if (credWrite == null || credRead == null || credDelete == null || credFree == null) {
                arena.close()
                return null
            }
            return Win32Bindings(arena, credWrite, credRead, credDelete, credFree)
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
