package dev.hivens.libvault.macos

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle

/**
 * Panama bindings to macOS Keychain Services (`SecItem*`) + the CoreFoundation
 * glue, plus the raw store/retrieve/delete marshalling keyed by `(service,
 * account)`. Items are generic passwords in the user's login Keychain, encrypted
 * by `securityd` under the login password (Secure Enclave-bound on Apple
 * Silicon).
 *
 * ```c
 * OSStatus SecItemAdd          (CFDictionaryRef attrs, CFTypeRef *result);
 * OSStatus SecItemCopyMatching (CFDictionaryRef query, CFTypeRef *result);
 * OSStatus SecItemUpdate       (CFDictionaryRef query, CFDictionaryRef attrsToUpdate);
 * OSStatus SecItemDelete       (CFDictionaryRef query);
 * ```
 *
 * Ported from the reviewed Aura/Nexira Keychain backend. Untested on a physical
 * Mac at write time -- the layout follows Apple's documented C ABI and the
 * Linux/Windows peers cross-check the shape. A real-Mac store/retrieve
 * miscompare is a bug report against this file.
 */
internal class SecurityBindings private constructor(
    private val arena: Arena,
    private val secItemAdd: MethodHandle,
    private val secItemCopyMatching: MethodHandle,
    private val secItemUpdate: MethodHandle,
    private val secItemDelete: MethodHandle,
    private val cfRelease: MethodHandle,
    private val cfStringCreate: MethodHandle,
    private val cfDataCreate: MethodHandle,
    private val cfDictionaryCreate: MethodHandle,
    private val cfDataGetBytePtr: MethodHandle,
    private val cfDataGetLength: MethodHandle,
    private val kSecClass: MemorySegment,
    private val kSecClassGenericPassword: MemorySegment,
    private val kSecAttrService: MemorySegment,
    private val kSecAttrAccount: MemorySegment,
    private val kSecValueData: MemorySegment,
    private val kSecReturnData: MemorySegment,
    private val kCFBooleanTrue: MemorySegment,
    private val keyCallBacks: MemorySegment,
    private val valueCallBacks: MemorySegment,
) {

    fun store(service: String, account: String, secret: ByteArray): Boolean = Arena.ofConfined().use { call ->
        val refs = mutableListOf<MemorySegment>()
        try {
            val serviceCF = cfString(call, service).also { refs += it }
            val accountCF = cfString(call, account).also { refs += it }
            val dataCF = cfData(call, secret).also { refs += it }

            val addQuery = cfDictionary(
                call,
                arrayOf(kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData),
                arrayOf(kSecClassGenericPassword, serviceCF, accountCF, dataCF),
            ).also { refs += it }

            var status = secItemAdd.invokeExact(addQuery, MemorySegment.NULL) as Int
            if (status == ERR_DUPLICATE_ITEM) {
                val locator = cfDictionary(
                    call,
                    arrayOf(kSecClass, kSecAttrService, kSecAttrAccount),
                    arrayOf(kSecClassGenericPassword, serviceCF, accountCF),
                ).also { refs += it }
                val updates = cfDictionary(call, arrayOf(kSecValueData), arrayOf(dataCF)).also { refs += it }
                status = secItemUpdate.invokeExact(locator, updates) as Int
            }
            status == ERR_SUCCESS
        } catch (t: Throwable) {
            false
        } finally {
            releaseAll(refs)
        }
    }

    fun retrieve(service: String, account: String): ByteArray? = Arena.ofConfined().use { call ->
        val refs = mutableListOf<MemorySegment>()
        try {
            val serviceCF = cfString(call, service).also { refs += it }
            val accountCF = cfString(call, account).also { refs += it }
            val query = cfDictionary(
                call,
                arrayOf(kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData),
                arrayOf(kSecClassGenericPassword, serviceCF, accountCF, kCFBooleanTrue),
            ).also { refs += it }

            val outPtr = call.allocate(ValueLayout.ADDRESS)
            val status = secItemCopyMatching.invokeExact(query, outPtr) as Int
            if (status != ERR_SUCCESS) return@use null
            val cfDataRef = outPtr.get(ValueLayout.ADDRESS, 0)
            if (cfDataRef.address() == 0L) return@use null
            // CopyMatching's result is caller-owned -- track it for release too.
            refs += cfDataRef
            val length = cfDataGetLength.invokeExact(cfDataRef) as Long
            val ptr = cfDataGetBytePtr.invokeExact(cfDataRef) as MemorySegment
            if (length > 0 && ptr.address() != 0L) {
                ptr.reinterpret(length).toArray(ValueLayout.JAVA_BYTE)
            } else {
                ByteArray(0)
            }
        } catch (t: Throwable) {
            null
        } finally {
            releaseAll(refs)
        }
    }

    fun delete(service: String, account: String): Boolean = Arena.ofConfined().use { call ->
        val refs = mutableListOf<MemorySegment>()
        try {
            val serviceCF = cfString(call, service).also { refs += it }
            val accountCF = cfString(call, account).also { refs += it }
            val query = cfDictionary(
                call,
                arrayOf(kSecClass, kSecAttrService, kSecAttrAccount),
                arrayOf(kSecClassGenericPassword, serviceCF, accountCF),
            ).also { refs += it }
            val status = secItemDelete.invokeExact(query) as Int
            // Idempotent: nothing to delete is success.
            status == ERR_SUCCESS || status == ERR_ITEM_NOT_FOUND
        } catch (t: Throwable) {
            false
        } finally {
            releaseAll(refs)
        }
    }

    fun close() {
        runCatching { arena.close() }
    }

    // ── CoreFoundation marshalling ─────────────────────────────────────────────

    private fun cfString(call: Arena, s: String): MemorySegment {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val buf = call.allocate(bytes.size.toLong().coerceAtLeast(1))
        if (bytes.isNotEmpty()) MemorySegment.copy(bytes, 0, buf, ValueLayout.JAVA_BYTE, 0, bytes.size)
        return cfStringCreate.invokeExact(
            MemorySegment.NULL, buf, bytes.size.toLong(), CF_ENCODING_UTF8, 0.toByte(),
        ) as MemorySegment
    }

    private fun cfData(call: Arena, bytes: ByteArray): MemorySegment {
        val buf = call.allocate(bytes.size.toLong().coerceAtLeast(1))
        if (bytes.isNotEmpty()) MemorySegment.copy(bytes, 0, buf, ValueLayout.JAVA_BYTE, 0, bytes.size)
        return cfDataCreate.invokeExact(MemorySegment.NULL, buf, bytes.size.toLong()) as MemorySegment
    }

    private fun cfDictionary(call: Arena, keys: Array<MemorySegment>, values: Array<MemorySegment>): MemorySegment {
        val n = keys.size
        val keysBuf = call.allocate(ValueLayout.ADDRESS, n.toLong())
        val valuesBuf = call.allocate(ValueLayout.ADDRESS, n.toLong())
        for (i in 0 until n) {
            keysBuf.setAtIndex(ValueLayout.ADDRESS, i.toLong(), keys[i])
            valuesBuf.setAtIndex(ValueLayout.ADDRESS, i.toLong(), values[i])
        }
        return cfDictionaryCreate.invokeExact(
            MemorySegment.NULL, keysBuf, valuesBuf, n.toLong(), keyCallBacks, valueCallBacks,
        ) as MemorySegment
    }

    private fun releaseAll(refs: List<MemorySegment>) {
        for (ref in refs) {
            if (ref.address() == 0L) continue
            runCatching { cfRelease.invokeExact(ref) as Unit }
        }
    }

    companion object {
        private const val SECURITY = "/System/Library/Frameworks/Security.framework/Security"
        private const val CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        private const val ERR_SUCCESS = 0
        private const val ERR_ITEM_NOT_FOUND = -25300
        private const val ERR_DUPLICATE_ITEM = -25299
        private const val CF_ENCODING_UTF8 = 0x08000100

        fun load(): SecurityBindings? {
            val arena = Arena.ofShared()
            val security = runCatching { SymbolLookup.libraryLookup(SECURITY, arena) }.getOrNull()
            val cf = runCatching { SymbolLookup.libraryLookup(CORE_FOUNDATION, arena) }.getOrNull()
            if (security == null || cf == null) {
                arena.close()
                return null
            }

            val secItemAdd = security.downcall("SecItemAdd", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
            val secItemCopy = security.downcall("SecItemCopyMatching", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
            val secItemUpdate = security.downcall("SecItemUpdate", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
            val secItemDelete = security.downcall("SecItemDelete", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS))
            val cfRelease = cf.downcall("CFRelease", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS))
            val cfStringCreate = cf.downcall(
                "CFStringCreateWithBytes",
                FunctionDescriptor.of(
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_BYTE,
                ),
            )
            val cfDataCreate = cf.downcall(
                "CFDataCreate",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            )
            val cfDictionaryCreate = cf.downcall(
                "CFDictionaryCreate",
                FunctionDescriptor.of(
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                ),
            )
            val cfDataGetBytePtr = cf.downcall("CFDataGetBytePtr", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS))
            val cfDataGetLength = cf.downcall("CFDataGetLength", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS))

            val kSecClass = derefCFConstant(security, "kSecClass")
            val kSecClassGenericPassword = derefCFConstant(security, "kSecClassGenericPassword")
            val kSecAttrService = derefCFConstant(security, "kSecAttrService")
            val kSecAttrAccount = derefCFConstant(security, "kSecAttrAccount")
            val kSecValueData = derefCFConstant(security, "kSecValueData")
            val kSecReturnData = derefCFConstant(security, "kSecReturnData")
            val kCFBooleanTrue = derefCFConstant(cf, "kCFBooleanTrue")
            val keyCallBacks = cf.find("kCFTypeDictionaryKeyCallBacks").orElse(null)
            val valueCallBacks = cf.find("kCFTypeDictionaryValueCallBacks").orElse(null)

            if (secItemAdd == null || secItemCopy == null || secItemUpdate == null || secItemDelete == null ||
                cfRelease == null || cfStringCreate == null || cfDataCreate == null || cfDictionaryCreate == null ||
                cfDataGetBytePtr == null || cfDataGetLength == null ||
                kSecClass == null || kSecClassGenericPassword == null || kSecAttrService == null ||
                kSecAttrAccount == null || kSecValueData == null || kSecReturnData == null || kCFBooleanTrue == null ||
                keyCallBacks == null || valueCallBacks == null
            ) {
                arena.close()
                return null
            }

            return SecurityBindings(
                arena, secItemAdd, secItemCopy, secItemUpdate, secItemDelete, cfRelease, cfStringCreate,
                cfDataCreate, cfDictionaryCreate, cfDataGetBytePtr, cfDataGetLength,
                kSecClass, kSecClassGenericPassword, kSecAttrService, kSecAttrAccount, kSecValueData,
                kSecReturnData, kCFBooleanTrue, keyCallBacks, valueCallBacks,
            )
        }

        private fun derefCFConstant(lookup: SymbolLookup, name: String): MemorySegment? {
            val storage = lookup.find(name).orElse(null) ?: return null
            return storage.reinterpret(8).get(ValueLayout.ADDRESS, 0).takeIf { it.address() != 0L }
        }
    }
}

private fun SymbolLookup.downcall(name: String, descriptor: FunctionDescriptor): MethodHandle? {
    val symbol = find(name).orElse(null) ?: return null
    return Linker.nativeLinker().downcallHandle(symbol, descriptor)
}
