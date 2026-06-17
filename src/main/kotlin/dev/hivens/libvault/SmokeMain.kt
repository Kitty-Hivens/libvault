package dev.hivens.libvault

import org.slf4j.LoggerFactory

/**
 * Manual smoke harness: `./gradlew runSmoke [--args="namespace unlock"]`.
 *
 * Probes the OS keyring (so you see Locked vs Available live), opens the best
 * vault, and runs the store/retrieve/list/describe round-trip plus capability
 * discovery. Pass `unlock` to open with [UnlockPolicy.IfLocked] -- that surfaces
 * the system unlock prompt on a locked keyring, so only do it interactively.
 */
public fun main(args: Array<String>) {
    val log = LoggerFactory.getLogger("libvault.Smoke")
    val wantUnlock = "unlock" in args
    val namespace = args.firstOrNull { it != "unlock" } ?: "dev.hivens.libvault.smoke"

    // 1. Probe -- distinguishes a locked keyring from an absent one.
    Vault.probe(VaultConfig(namespace = namespace)).forEach {
        log.info("probe: tier={} backend={} availability={} usable={}", it.tier, it.backend, it.availability, it.usable)
    }

    val config = VaultConfig(
        namespace = namespace,
        unlockPolicy = if (wantUnlock) UnlockPolicy.IfLocked else UnlockPolicy.Never,
    )

    Vault.open(config).use { vault ->
        log.info("opened: tier={} backend={} secure={}", vault.tier, vault.backend, vault.secure)

        val secret = "hunter2-${ProcessHandle.current().pid()}".toByteArray()
        log.info("store -> {}", vault.store("smoke-token", secret))
        val read = vault.retrieve("smoke-token")
        log.info("retrieve -> {}", if (read != null) "${read.size} bytes, matches=${read.contentEquals(secret)}" else "null")

        vault.asLabeled()?.store("smoke-labeled", secret, label = "Smoke Label", attributes = mapOf("kind" to "test"))
        vault.asDescribable()?.describe("smoke-labeled")?.let {
            log.info("describe -> label={} created={} modified={} attrs={}", it.label, it.created, it.modified, it.attributes)
        }
        vault.asEnumerable()?.let { log.info("list -> {}", it.list()) }
        vault.asUnlockable()?.let { log.info("isLocked -> {}", it.isLocked()) }

        val removed = vault.asEnumerable()?.clear()
        log.info("clear -> {} removed", removed)
    }
}
