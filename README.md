# libvault

Cross-platform secret storage for the JVM. One small API in front of the
operating system's own credential store, with an encrypted-file fallback when no
keyring is reachable -- and a hard rule that it never blocks the caller.

Pure [Project Panama](https://openjdk.org/projects/panama/) (`java.lang.foreign`):
no JNA, no dbus-java, no runtime libsecret. The only runtime dependencies are
SLF4J (logging) and BouncyCastle (Argon2id, used solely by the passphrase
software tier). JVM 22+.

Part of the same family as [libtray](https://github.com/Kitty-Hivens/libtray)
and [libnotify](https://github.com/Kitty-Hivens/libnotify).

## What it does

- **Tiered + soft.** OS keyring first, then an AES-256-GCM file, then optionally
  in-memory or nothing. `Vault.open()` always returns a working store.
- **Honest.** The vault reports its [tier] and whether it is `secure`
  (OS-backed) or merely obfuscated.
- **Never hangs.** Both backend selection and every individual operation are
  bounded by a timeout. A locked, prompt-only, or wedged keyring service
  degrades to the fallback -- it does not block.

| Platform | Tier-1 backend | Transport |
| --- | --- | --- |
| Linux / BSD | Secret Service | D-Bus over `libdbus-1` (Panama) |
| Windows | Credential Manager (DPAPI) | `Advapi32` (Panama) |
| macOS | Keychain Services | `Security.framework` (Panama) |
| any | AES-256-GCM file | pure JDK `javax.crypto` + BouncyCastle Argon2id |

## Use

```kotlin
import dev.hivens.libvault.Vault
import dev.hivens.libvault.VaultConfig

Vault.open(VaultConfig(namespace = "dev.hivens.nexira")).use { vault ->
    vault.store("accessToken", tokenBytes)          // upsert
    val token = vault.retrieve("accessToken")       // null if absent/unreachable
    vault.delete("accessToken")

    // Text secrets without an interned String:
    vault.storeString("password", passwordChars)
    val pw = vault.retrieveString("password")        // CharArray, caller zeroes it

    println("tier=${vault.tier} secure=${vault.secure}")
}
```

`store`/`delete` return a boolean; `retrieve`/`contains` return null/false rather
than throw. The only thing the API throws is `IllegalArgumentException` on a blank
namespace or key. `Vault.open` never throws on a backend fault.

## Configuration

```kotlin
VaultConfig(
    namespace = "dev.hivens.nexira",      // scopes every key; required, non-blank
    allowSoftwareFallback = true,         // false = OS keyring or nothing
    softwareFilePath = null,              // null -> OS data dir / namespace / vault.bin
    keyDerivation = KeyDerivation.MachineBound,   // or Passphrase(chars)
    probeTimeoutMs = 1500,                // ceiling on backend selection
    opTimeoutMs = 2000,                   // ceiling on one keyring operation
    preferredTiers = listOf(VaultTier.OsKeyring, VaultTier.SoftwareFile),
)
```

The software tier derives its AES key either from machine-local material
(`MachineBound`, PBKDF2, zero friction, obfuscation only) or from a caller
passphrase (`Passphrase`, Argon2id, strong but needs the passphrase each run).
Either way that tier reports `secure = false`: it is defense against a casual
file copy, not against a local attacker running as the same user.

When the OS keyring exists but its collection is locked behind an interactive
prompt, libvault does NOT prompt -- it degrades to the software file (or to
`None`, if the fallback is disabled). Prompt/unlock UI is out of scope; the
caller inspects `tier` / `secure` and decides.

## Install

```toml
# gradle/libs.versions.toml
[libraries]
libvault = { group = "dev.hivens", name = "libvault", version = "0.1.0" }
```

```kotlin
dependencies {
    implementation(libs.libvault)
}
```

The OS-keyring backends use Panama downcalls, so the consuming application must
launch with `--enable-native-access=ALL-UNNAMED` (or the specific module).

## Build

Java 22+ on the build PATH.

```
./gradlew build          # compile + test
./gradlew runSmoke        # store/retrieve/delete against the live OS keyring
./gradlew publishToMavenCentral -PappVersion=0.1.0
```
