package dev.hivens.libvault.macos

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle

/**
 * Panama bindings to macOS Keychain Services (`SecItem*`) + CoreFoundation glue,
 * plus raw store/retrieve/delete/enumerate/describe marshalling keyed by
 * `(service, account)`. Items are generic passwords in the login Keychain.
 *
 * Ported and extended from the reviewed Aura/Nexira Keychain backend. Untested on
 * a physical Mac at write time -- the layouts follow Apple's documented C ABI and
 * the Linux/Windows peers cross-check the shape.
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
    private val cfArrayGetCount: MethodHandle,
    private val cfArrayGetValueAtIndex: MethodHandle,
    private val cfDictionaryGetValue: MethodHandle,
    private val cfStringGetCString: MethodHandle,
    private val cfDateGetAbsoluteTime: MethodHandle,
    private val c: Constants,
) {

    /** Deref'd kSec/kCF constants, grouped so the constructor stays readable. */
    internal class Constants(
        val kSecClass: MemorySegment,
        val kSecClassGenericPassword: MemorySegment,
        val kSecAttrService: MemorySegment,
        val kSecAttrAccount: MemorySegment,
        val kSecValueData: MemorySegment,
        val kSecReturnData: MemorySegment,
        val kSecReturnAttributes: MemorySegment,
        val kSecMatchLimit: MemorySegment,
        val kSecMatchLimitAll: MemorySegment,
        val kSecAttrLabel: MemorySegment,
        val kSecAttrCreationDate: MemorySegment?,
        val kSecAttrModificationDate: MemorySegment?,
        val kSecAttrAccessible: MemorySegment?,
        val accessibleValues: Map<String, MemorySegment>,
        val kCFBooleanTrue: MemorySegment,
        val keyCallBacks: MemorySegment,
        val valueCallBacks: MemorySegment,
    )

    /** Read-side attributes for one item. */
    class Meta(val label: String?, val createdSeconds: Long, val modifiedSeconds: Long)

    fun store(service: String, account: String, secret: ByteArray, label: String?, accessibilityName: String): Boolean =
        Arena.ofConfined().use { call ->
            val refs = mutableListOf<MemorySegment>()
            try {
                val serviceCF = cfString(call, service).also { refs += it }
                val accountCF = cfString(call, account).also { refs += it }
                val dataCF = cfData(call, secret).also { refs += it }

                val addKeys = mutableListOf(c.kSecClass, c.kSecAttrService, c.kSecAttrAccount, c.kSecValueData)
                val addVals = mutableListOf(c.kSecClassGenericPassword, serviceCF, accountCF, dataCF)
                if (label != null) {
                    addKeys += c.kSecAttrLabel
                    addVals += cfString(call, label).also { refs += it }
                }
                val accessible = c.kSecAttrAccessible
                val accessibleVal = c.accessibleValues[accessibilityName]
                if (accessible != null && accessibleVal != null) {
                    addKeys += accessible
                    addVals += accessibleVal
                }

                val addQuery = cfDictionary(call, addKeys.toTypedArray(), addVals.toTypedArray()).also { refs += it }

                var status = secItemAdd.invokeExact(addQuery, MemorySegment.NULL) as Int
                if (status == ERR_DUPLICATE_ITEM) {
                    val locator = cfDictionary(
                        call,
                        arrayOf(c.kSecClass, c.kSecAttrService, c.kSecAttrAccount),
                        arrayOf(c.kSecClassGenericPassword, serviceCF, accountCF),
                    ).also { refs += it }
                    val updates = cfDictionary(call, arrayOf(c.kSecValueData), arrayOf(dataCF)).also { refs += it }
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
                arrayOf(c.kSecClass, c.kSecAttrService, c.kSecAttrAccount, c.kSecReturnData),
                arrayOf(c.kSecClassGenericPassword, serviceCF, accountCF, c.kCFBooleanTrue),
            ).also { refs += it }

            val outPtr = call.allocate(ValueLayout.ADDRESS)
            val status = secItemCopyMatching.invokeExact(query, outPtr) as Int
            if (status != ERR_SUCCESS) return@use null
            val cfDataRef = outPtr.get(ValueLayout.ADDRESS, 0)
            if (cfDataRef.address() == 0L) return@use null
            refs += cfDataRef
            val length = cfDataGetLength.invokeExact(cfDataRef) as Long
            val ptr = cfDataGetBytePtr.invokeExact(cfDataRef) as MemorySegment
            if (length > 0 && ptr.address() != 0L) ptr.reinterpret(length).toArray(ValueLayout.JAVA_BYTE) else ByteArray(0)
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
                arrayOf(c.kSecClass, c.kSecAttrService, c.kSecAttrAccount),
                arrayOf(c.kSecClassGenericPassword, serviceCF, accountCF),
            ).also { refs += it }
            val status = secItemDelete.invokeExact(query) as Int
            status == ERR_SUCCESS || status == ERR_ITEM_NOT_FOUND
        } catch (t: Throwable) {
            false
        } finally {
            releaseAll(refs)
        }
    }

    /** Accounts under [service]. Empty on fault. */
    fun enumerate(service: String): List<String> = Arena.ofConfined().use { call ->
        val refs = mutableListOf<MemorySegment>()
        try {
            val serviceCF = cfString(call, service).also { refs += it }
            val query = cfDictionary(
                call,
                arrayOf(c.kSecClass, c.kSecAttrService, c.kSecMatchLimit, c.kSecReturnAttributes),
                arrayOf(c.kSecClassGenericPassword, serviceCF, c.kSecMatchLimitAll, c.kCFBooleanTrue),
            ).also { refs += it }

            val outPtr = call.allocate(ValueLayout.ADDRESS)
            val status = secItemCopyMatching.invokeExact(query, outPtr) as Int
            if (status != ERR_SUCCESS) return@use emptyList<String>()
            val arrayRef = outPtr.get(ValueLayout.ADDRESS, 0)
            if (arrayRef.address() == 0L) return@use emptyList<String>()
            refs += arrayRef
            val count = cfArrayGetCount.invokeExact(arrayRef) as Long
            val out = ArrayList<String>(count.toInt().coerceAtLeast(0))
            for (i in 0 until count) {
                val dict = cfArrayGetValueAtIndex.invokeExact(arrayRef, i) as MemorySegment
                if (dict.address() == 0L) continue
                val accountRef = cfDictionaryGetValue.invokeExact(dict, c.kSecAttrAccount) as MemorySegment
                cfStringToJava(call, accountRef)?.let { out += it }
            }
            out
        } catch (t: Throwable) {
            emptyList()
        } finally {
            releaseAll(refs)
        }
    }

    fun describe(service: String, account: String): Meta? = Arena.ofConfined().use { call ->
        val refs = mutableListOf<MemorySegment>()
        try {
            val serviceCF = cfString(call, service).also { refs += it }
            val accountCF = cfString(call, account).also { refs += it }
            val query = cfDictionary(
                call,
                arrayOf(c.kSecClass, c.kSecAttrService, c.kSecAttrAccount, c.kSecReturnAttributes),
                arrayOf(c.kSecClassGenericPassword, serviceCF, accountCF, c.kCFBooleanTrue),
            ).also { refs += it }

            val outPtr = call.allocate(ValueLayout.ADDRESS)
            val status = secItemCopyMatching.invokeExact(query, outPtr) as Int
            if (status != ERR_SUCCESS) return@use null
            val dict = outPtr.get(ValueLayout.ADDRESS, 0)
            if (dict.address() == 0L) return@use null
            refs += dict
            val label = cfStringToJava(call, cfDictionaryGetValue.invokeExact(dict, c.kSecAttrLabel) as MemorySegment)
            val created = c.kSecAttrCreationDate?.let { cfDateSeconds(cfDictionaryGetValue.invokeExact(dict, it) as MemorySegment) } ?: 0
            val modified = c.kSecAttrModificationDate?.let { cfDateSeconds(cfDictionaryGetValue.invokeExact(dict, it) as MemorySegment) } ?: 0
            Meta(label, created, modified)
        } catch (t: Throwable) {
            null
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
        return cfStringCreate.invokeExact(MemorySegment.NULL, buf, bytes.size.toLong(), CF_ENCODING_UTF8, 0.toByte()) as MemorySegment
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
            MemorySegment.NULL, keysBuf, valuesBuf, n.toLong(), c.keyCallBacks, c.valueCallBacks,
        ) as MemorySegment
    }

    private fun cfStringToJava(call: Arena, str: MemorySegment): String? {
        if (str.address() == 0L) return null
        val cap = 2048L
        val buf = call.allocate(cap)
        val ok = cfStringGetCString.invokeExact(str, buf, cap, CF_ENCODING_UTF8) as Int
        return if (ok == 0) null else buf.reinterpret(cap).getString(0, Charsets.UTF_8)
    }

    private fun cfDateSeconds(date: MemorySegment): Long {
        if (date.address() == 0L) return 0
        val abs = cfDateGetAbsoluteTime.invokeExact(date) as Double // seconds since 2001-01-01
        if (abs == 0.0) return 0
        return (abs + CF_ABSOLUTE_EPOCH_OFFSET).toLong()
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

        // Seconds between the Unix epoch (1970) and the CF reference date (2001).
        private const val CF_ABSOLUTE_EPOCH_OFFSET = 978_307_200.0

        private val ACCESSIBLE_NAMES = listOf(
            "kSecAttrAccessibleWhenUnlocked",
            "kSecAttrAccessibleAfterFirstUnlock",
            "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
            "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        )

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
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_BYTE),
            )
            val cfDataCreate = cf.downcall("CFDataCreate", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG))
            val cfDictionaryCreate = cf.downcall(
                "CFDictionaryCreate",
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
            )
            val cfDataGetBytePtr = cf.downcall("CFDataGetBytePtr", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS))
            val cfDataGetLength = cf.downcall("CFDataGetLength", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS))
            val cfArrayGetCount = cf.downcall("CFArrayGetCount", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS))
            val cfArrayGetValueAtIndex = cf.downcall("CFArrayGetValueAtIndex", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG))
            val cfDictionaryGetValue = cf.downcall("CFDictionaryGetValue", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS))
            val cfStringGetCString = cf.downcall("CFStringGetCString", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT))
            val cfDateGetAbsoluteTime = cf.downcall("CFDateGetAbsoluteTime", FunctionDescriptor.of(ValueLayout.JAVA_DOUBLE, ValueLayout.ADDRESS))

            val kSecClass = derefCFConstant(security, "kSecClass")
            val kSecClassGenericPassword = derefCFConstant(security, "kSecClassGenericPassword")
            val kSecAttrService = derefCFConstant(security, "kSecAttrService")
            val kSecAttrAccount = derefCFConstant(security, "kSecAttrAccount")
            val kSecValueData = derefCFConstant(security, "kSecValueData")
            val kSecReturnData = derefCFConstant(security, "kSecReturnData")
            val kSecReturnAttributes = derefCFConstant(security, "kSecReturnAttributes")
            val kSecMatchLimit = derefCFConstant(security, "kSecMatchLimit")
            val kSecMatchLimitAll = derefCFConstant(security, "kSecMatchLimitAll")
            val kSecAttrLabel = derefCFConstant(security, "kSecAttrLabel")
            val kSecAttrCreationDate = derefCFConstant(security, "kSecAttrCreationDate")
            val kSecAttrModificationDate = derefCFConstant(security, "kSecAttrModificationDate")
            val kSecAttrAccessible = derefCFConstant(security, "kSecAttrAccessible")
            val accessibleValues = ACCESSIBLE_NAMES.mapNotNull { name ->
                derefCFConstant(security, name)?.let { name to it }
            }.toMap()
            val kCFBooleanTrue = derefCFConstant(cf, "kCFBooleanTrue")
            val keyCallBacks = cf.find("kCFTypeDictionaryKeyCallBacks").orElse(null)
            val valueCallBacks = cf.find("kCFTypeDictionaryValueCallBacks").orElse(null)

            if (secItemAdd == null || secItemCopy == null || secItemUpdate == null || secItemDelete == null ||
                cfRelease == null || cfStringCreate == null || cfDataCreate == null || cfDictionaryCreate == null ||
                cfDataGetBytePtr == null || cfDataGetLength == null || cfArrayGetCount == null ||
                cfArrayGetValueAtIndex == null || cfDictionaryGetValue == null || cfStringGetCString == null ||
                cfDateGetAbsoluteTime == null ||
                kSecClass == null || kSecClassGenericPassword == null || kSecAttrService == null ||
                kSecAttrAccount == null || kSecValueData == null || kSecReturnData == null ||
                kSecReturnAttributes == null || kSecMatchLimit == null || kSecMatchLimitAll == null ||
                kSecAttrLabel == null || kCFBooleanTrue == null || keyCallBacks == null || valueCallBacks == null
            ) {
                arena.close()
                return null
            }

            val constants = Constants(
                kSecClass, kSecClassGenericPassword, kSecAttrService, kSecAttrAccount, kSecValueData,
                kSecReturnData, kSecReturnAttributes, kSecMatchLimit, kSecMatchLimitAll, kSecAttrLabel,
                kSecAttrCreationDate, kSecAttrModificationDate, kSecAttrAccessible, accessibleValues,
                kCFBooleanTrue, keyCallBacks, valueCallBacks,
            )
            return SecurityBindings(
                arena, secItemAdd, secItemCopy, secItemUpdate, secItemDelete, cfRelease, cfStringCreate,
                cfDataCreate, cfDictionaryCreate, cfDataGetBytePtr, cfDataGetLength, cfArrayGetCount,
                cfArrayGetValueAtIndex, cfDictionaryGetValue, cfStringGetCString, cfDateGetAbsoluteTime, constants,
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
