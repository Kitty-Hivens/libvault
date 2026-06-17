package dev.hivens.libvault

import org.slf4j.LoggerFactory

/**
 * Manual smoke harness: `./gradlew runSmoke`. Opens the best vault for this
 * host, reports the tier it resolved to, and runs a store -> retrieve -> delete
 * round-trip against it. Not a test (no assertions framework, needs a live OS
 * keyring) -- it's how a human eyeballs that the real backend works on a real
 * desktop.
 */
public fun main(args: Array<String>) {
    val log = LoggerFactory.getLogger("libvault.Smoke")
    val namespace = args.firstOrNull() ?: "dev.hivens.libvault.smoke"

    Vault.open(VaultConfig(namespace = namespace)).use { vault ->
        log.info("opened: tier={} backend={} secure={}", vault.tier, vault.backend, vault.secure)

        val key = "smoke-token"
        val secret = "hunter2-${ProcessHandle.current().pid()}".toByteArray()

        log.info("store -> {}", vault.store(key, secret))
        val read = vault.retrieve(key)
        log.info("retrieve -> {}", if (read != null) "${read.size} bytes, matches=${read.contentEquals(secret)}" else "null")
        log.info("contains -> {}", vault.contains(key))
        log.info("delete -> {}", vault.delete(key))
        log.info("contains after delete -> {}", vault.contains(key))
    }
}
