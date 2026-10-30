# libvault

Cross-platform secret storage for the JVM and Android. One small API in front of
the operating system's own credential store, with an encrypted-file fallback when
no keyring is reachable -- and a hard rule that it never blocks the caller.

On the desktop it is pure [Project Panama](https://openjdk.org/projects/panama/)
(`java.lang.foreign`): no JNA, no dbus-java, no runtime libsecret. On Android it
is the platform's own Keystore API, with no native code at all. The only runtime
dependencies are SLF4J (logging) and BouncyCastle (Argon2id, used solely by the
passphrase software tier).

Part of the same family as [libtray](https://github.com/Kitty-Hivens/libtray)
and [libnotify](https://github.com/Kitty-Hivens/libnotify).

## What it does

- **Tiered + soft.** OS keyring first, then an AES-256-GCM file, then optionally
  in-memory or nothing. `open()` always returns a working store.
- **Honest.** The vault reports its tier and whether it is `secure`
  (OS-backed) or merely obfuscated.
- **Never hangs.** Both backend selection and every individual operation are
  bounded by a timeout. A locked, prompt-only, or wedged keyring service
  degrades to the fallback -- it does not block.

| Platform    | Tier-1 backend             | Transport                                       |
|-------------|----------------------------|-------------------------------------------------|
| Linux / BSD | Secret Service             | D-Bus over `libdbus-1` (Panama)                 |
| Windows     | Credential Manager (DPAPI) | `Advapi32` (Panama)                             |
| macOS       | Keychain Services          | `Security.framework` (Panama)                   |
| Android     | Android Keystore           | `AndroidKeyStore` JCA provider                  |
| any         | AES-256-GCM file           | pure JDK `javax.crypto` + BouncyCastle Argon2id |

## Modules

| Artifact                      | Runtime     | What is in it                                                      |
|-------------------------------|-------------|--------------------------------------------------------------------|
| `dev.hivens:libvault`         | JVM 22+     | `Vault`, the Secret Service, Credential Manager and Keychain tiers |
| `dev.hivens:libvault-android` | Android 8+  | `AndroidVault`, the Android Keystore tier                          |
| `dev.hivens:libvault-core`    | JVM 17+     | The API, the file, memory and none tiers. Comes with either above  |

A desktop application depends on `libvault`, an Android one on
`libvault-android`. Both bring `libvault-core` along, and the code that uses a
vault is the same on both.

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
namespace or key. `open` never throws on a backend fault.

### On Android

The same, with a `Context`:

```kotlin
import dev.hivens.libvault.android.AndroidVault

AndroidVault.open(context, VaultConfig(namespace = "dev.hivens.nexira")).use { vault ->
    vault.store("accessToken", tokenBytes)
}
```

Secrets are encrypted with AES-256-GCM under a key that lives in the Android
Keystore (in the TEE where the device has one) and is never exportable. Only
the ciphertext is written, to the app's no-backup directory: the key never
leaves the device, so a file restored from a backup could not be opened anyway,
and secrets have no business in a cloud backup.

Call `open` off the main thread. The first open generates the key, and a
Keystore can take a moment to answer. Keys need no user authentication, so the
store is never locked. `VaultConfig.accessibility` does not apply: the files
live in credential-encrypted storage, readable from the first unlock after
boot. Logging goes through SLF4J. Without a binding on the classpath it is
silent.

## Capabilities

Beyond the five base methods, optional features live on sub-interfaces a backend
implements only when it can. Discover them with the `asX()` helpers (null = not
supported here):

```kotlin
vault.asEnumerable()?.list()                    // all keys in the namespace; clear() wipes them
vault.asDescribable()?.describe("accessToken")  // label / created / modified / attributes
vault.asLabeled()?.store("k", bytes, label = "My App", attributes = mapOf("env" to "prod"))
vault.asMigratable()?.migrateTo(other, deleteAfter = true)
vault.asWatchable()?.onWatch { change -> /* item changed externally (Linux) */ }
```

### Unlocking a locked keyring

`Vault.open` never prompts -- a locked keyring degrades to the file tier. To offer
an unlock, probe first, then open with the opt-in policy:

```kotlin
val locked = Vault.probe(config).any {
    it.tier == VaultTier.OsKeyring && it.availability == VaultAvailability.Locked
}
if (locked && userAgreed) {
    Vault.open(config.copy(unlockPolicy = UnlockPolicy.IfLocked)).use { vault ->
        // vault.secure is true if the user completed the system prompt
    }
}
```

On Linux this raises the Secret Service prompt and waits up to `unlockTimeoutMs`.
Windows/macOS keychains unlock with the login session and the Android Keystore
with the device, so there `unlock()` is a no-op that succeeds. For permanent
unlock-at-login on Linux, configure PAM (`pam_gnome_keyring`) rather than
calling this each run.

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

A vault file that does not open under the current key (a different passphrase,
changed machine material, a lost Keystore key, corruption) is never
overwritten. Reads report nothing, and the first write moves it aside to
`vault.bin.unreadable-<UTC time>` before starting a new file, so the old secrets
can still be recovered with the right key. Several processes may share one
file: writes are serialized through a lock file and none of them loses another's
records.

When the OS keyring exists but its collection is locked behind an interactive
prompt, libvault does NOT prompt -- it degrades to the software file (or to
`None`, if the fallback is disabled). Prompt/unlock UI is out of scope; the
caller inspects `tier` / `secure` and decides.

## Install

```toml
# gradle/libs.versions.toml
[versions]
libvault = "0.3.0"

[libraries]
libvault         = { group = "dev.hivens", name = "libvault",         version.ref = "libvault" }
libvault-android = { group = "dev.hivens", name = "libvault-android", version.ref = "libvault" }
```

```kotlin
dependencies {
    implementation(libs.libvault)          // desktop
    // implementation(libs.libvault.android)  // Android
}
```

The desktop keyring backends use Panama downcalls, so the consuming application
must launch with `--enable-native-access=ALL-UNNAMED`, or
`--enable-native-access=libvault` on the module path. The keyrings register
themselves for `Vault` through `META-INF/services`, which a fat jar has to keep.
The Android module needs minSdk 26 and declares no permissions.

## Build

Java 22+ on the build PATH, and an Android SDK (`ANDROID_HOME` or `sdk.dir` in
`local.properties`) for the Android module.

```
./gradlew build                                       # compile + test every module
./gradlew :libvault-desktop:runSmoke                  # store/retrieve/delete against the live OS keyring
./gradlew :libvault-android:connectedDebugAndroidTest # the Keystore tier, on an attached device or emulator
./gradlew publishToMavenCentral -PappVersion=0.3.0
```
