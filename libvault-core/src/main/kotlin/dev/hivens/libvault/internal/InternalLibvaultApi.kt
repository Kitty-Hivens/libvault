package dev.hivens.libvault.internal

/**
 * Marks the part of libvault-core that the platform modules share: backend
 * selection, the bounded single-thread base, the encrypted file format and its
 * key sources. None of it is offered to anybody else.
 *
 * It is public for one mechanical reason. libvault (desktop) and
 * libvault-android build on the same code, and a Kotlin `internal` cannot
 * cross a module boundary. This annotation says what `internal` would have
 * said: the surface can change in any release, and a consumer that opts in
 * owns the consequences.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "This is libvault's internal plumbing between its own modules. " +
        "Its surface carries no compatibility promise and may change in any release.",
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY)
public annotation class InternalLibvaultApi
