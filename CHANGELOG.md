# Changelog

All notable changes to libvault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release is a
`vX.Y.Z` tag, and its GitHub release carries that version's section below.

## [Unreleased]

### Added

- **Android.** `dev.hivens:libvault-android` and `AndroidVault.open(context, config)`.
  The OS keyring tier on Android encrypts secrets with AES-256-GCM under a
  non-exportable Android Keystore key and keeps only the ciphertext, in the
  app's no-backup directory. Same API, tiers, timeouts and failure model as
  the desktop library. A collection gets its own key and file. minSdk 26.
- **`dev.hivens:libvault-core`.** The API, the file, memory and none tiers and
  the backend selection, built for Java 17 with no Panama in it. Both
  `libvault` and `libvault-android` depend on it, so a desktop consumer's
  dependency and imports stay as they were.

### Changed

- The software file tier rereads the file when it changed on disk, and writes
  under an exclusive lock on a sibling `.lock` file. `opTimeoutMs` bounds the
  wait for that lock.
- Linux: the dispatch thread waits 100 ms instead of 25 ms between bus pumps
  when idle. Calls made through the library were never delayed by it, only
  the delivery of incoming signals.
- `Vault` lives in `libvault-core` and finds the desktop keyrings through a
  `ServiceLoader` registration in `libvault`, so the two jars share no package
  and still run on the module path, as module `libvault`. A fat jar has to keep
  `META-INF/services/dev.hivens.libvault.internal.KeyringBackend`.
- Builds with Gradle 9.7.1.

### Fixed

- The software file tier silently replaced a file it could not open (a
  mistyped passphrase, a changed machine id, hostname or home directory, a
  corrupt or newer file) on the first store, losing every secret in it. Such
  a file is now moved to `<name>.unreadable-<UTC time>` and a new one started.
- Two vaults on one file, in one process or in several, dropped each other's
  records on every write. Writes now reread the file under the lock.
- Windows: a vault without a collection listed every collection's entries as
  its own keys, and `clear()` deleted them. Entries now record their scope in
  the credential's UserName. Entries written before carry none: operations on
  one exact key use them as they always did and a store claims them, while
  `list()` and `clear()` attribute them by name, a slash after the namespace
  meaning a collection.
- Windows: a store refuses to overwrite a target that belongs to another
  scope instead of destroying its secret.
- Linux: the collection's lock state was checked once, at open. A collection
  that locked afterwards (an idle timeout, a screen lock) took every store as
  a success while gnome-keyring kept the item in memory only, and every read
  came back empty. Each store, retrieve, contains, delete and clear now
  checks the collection first, unlocking it where the service does that
  without a prompt, and fails without prompting otherwise. A store also reads
  the secret back before it reports success.
- macOS: storing an existing key with a new label kept the old label.
- Linux: `close()` could tear the D-Bus connection down while the dispatch
  thread was still inside a blocking call on it. Only the dispatch thread
  releases the connection now, and ops still queued at close return their
  default value at once.
- Linux, Windows and macOS: secret values no longer leave unzeroed plaintext
  copies in scratch buffers on the way to and from the keyring.

## [0.2.1] - 2026-06-19

### Fixed

- Linux: the Secret Service backend opens a private D-Bus connection
  (`dbus_bus_get_private`) instead of the process-shared `dbus_bus_get`
  one. A shared connection has a single incoming-message queue, so another
  libdbus user in the same process that runs its own
  `dbus_connection_pop_message` loop (a tray or notification library)
  could pop, and drop, messages destined for this backend, and vice
  versa. A private connection is drained solely by our own dispatch
  thread. `teardown()` now closes the private connection before the
  final unref. (`exit_on_disconnect` was already disabled.)

## [0.2.0] - 2026-06-17

A comprehensive capability pass. Everything is additive: 0.1.0 callers compile
and behave unchanged. The new features live on opt-in sub-interfaces discovered
via `as?` (`vault.asEnumerable()`, `asUnlockable()`, ...), so the five-method
`SecretVault` base stays the same.

### Added

- **Diagnostics.** `Vault.probe(config): List<VaultStatus>` classifies each
  tier without opening a live vault, distinguishing a *locked* keyring
  (`VaultAvailability.Locked`, offer an unlock) from an *absent* one
  (`ServiceUnavailable`, don't). Non-interactive.
- **Enumeration.** `EnumerableVault { list(); clear() }`.
- **Metadata.** `DescribableVault { describe(key): EntryMetadata? }`
  (label / created / modified / attributes).
- **Labels + attributes on store.** `LabeledVault.store(key, secret, label, attributes)`.
- **Interactive unlock / lock** (opt-in). `UnlockableVault { isLocked(); unlock(); lock() }`
  and `VaultConfig.unlockPolicy = IfLocked` / `unlockTimeoutMs`. Linux surfaces
  the Secret Service prompt and waits for `Completed`. Windows/macOS unlock with
  the login session (no-op). Default `Vault.open` never prompts.
- **Change-watch.** `WatchableVault.onWatch(cb)` delivering `VaultChange` from
  Secret Service item signals on Linux (inert on Windows/macOS).
- **Tier migration.** `MigratableVault.migrateTo(target, deleteAfter): MigrationReport`.
- **Custom collections.** `VaultConfig.collection` + `Vault.collections(config)`.
  A real named collection on Linux, a logical key prefix on Windows/macOS.
- **macOS accessibility.** `VaultConfig.accessibility` (`kSecAttrAccessible*`).

### Changed

- Software-file format bumped to **v2** (per-record timestamps + label +
  attributes). v1 files are still read.
- The Linux backend now runs a single dispatch-loop thread (bounded ops +
  persistent watch + transient unlock pump on one connection-safe thread).

### Out of scope (deferred)

- Hardware tier (TPM / Secure Enclave), async/coroutine API, iCloud sync.

## [0.1.0] - 2026-06-17

### Added

- Initial library: `Vault.open(VaultConfig)` returning a tiered `SecretVault`.
- OS-keyring backends over pure Project Panama:
  - Linux/BSD: Freedesktop Secret Service over `libdbus-1` (no runtime
    libsecret, no dbus-java).
  - Windows: Credential Manager / DPAPI over `Advapi32`.
  - macOS: Keychain Services over `Security.framework`.
- AES-256-GCM software-file fallback: versioned header, per-record nonce,
  key-bound AAD, verifier block, atomic writes. MachineBound (PBKDF2) and
  Passphrase (Argon2id) key derivation.
- Memory and None tiers.
- Per-operation and backend-selection timeouts. A locked or wedged keyring
  degrades instead of blocking. On a locked collection the backend declines to
  prompt and falls back.
- `storeString` / `retrieveString` that keep text secrets out of interned
  `String`s.
