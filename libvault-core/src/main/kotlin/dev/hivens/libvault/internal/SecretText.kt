package dev.hivens.libvault.internal

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * UTF-8 transcoding for text secrets that never lets the plaintext settle into
 * an immutable [String] (which would linger on the heap until GC, unzeroable).
 * Everything flows through scratch buffers the caller can wipe.
 *
 * The scratch buffers are heap arrays and are read and wiped through
 * `array()`. The Buffer methods that return their own type (`flip`, `clear`)
 * do so only from Java 9, and Android below API 34 has just the `Buffer` ones.
 */
internal object SecretText {

    /** Encode [chars] to UTF-8 bytes; the returned array is the caller's to zero. */
    fun toUtf8(chars: CharArray): ByteArray {
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        val charBuf = CharBuffer.wrap(chars)
        val byteBuf = ByteBuffer.allocate(
            (chars.size * encoder.maxBytesPerChar()).toInt().coerceAtLeast(1),
        )
        encoder.encode(charBuf, byteBuf, true)
        encoder.flush(byteBuf)
        val scratch = byteBuf.array()
        val out = scratch.copyOf(byteBuf.position())
        // Wipe the over-allocated scratch buffer so no UTF-8 tail survives in it.
        scratch.fill(0)
        return out
    }

    /** Decode UTF-8 [bytes] to a fresh [CharArray]; [bytes] is left untouched. */
    fun fromUtf8(bytes: ByteArray): CharArray {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        val byteBuf = ByteBuffer.wrap(bytes)
        val charBuf = CharBuffer.allocate(
            (bytes.size * decoder.maxCharsPerByte()).toInt().coerceAtLeast(1),
        )
        decoder.decode(byteBuf, charBuf, true)
        decoder.flush(charBuf)
        val scratch = charBuf.array()
        val out = scratch.copyOf(charBuf.position())
        // Wipe the scratch char buffer.
        scratch.fill('\u0000')
        return out
    }
}
