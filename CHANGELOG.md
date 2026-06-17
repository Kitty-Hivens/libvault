# Changelog

All notable changes to libvault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

A comprehensive capability pass. Everything is additive -- 0.1.0 callers compile
and behave unchanged; the new features live on opt-in sub-interfaces discovered
via `as?` (`vault.asEnumerable()`, `asUnlockable()`, ...), so the five-method
`SecretVault` base stays the same.

### Added

- **Diagnostics** -- `Vault.probe(config): List<VaultStatus>` classifies each
  tier without opening a live vault, distinguishing a *locked* keyring
  (`VaultAvailability.Locked` -- offer unlock) from an *absent* one
  (`ServiceUnavailable` -- don't). Non-interactive.
- **Enumeration** -- `EnumerableVault { list(); clear() }`.
- **Metadata** -- `DescribableVault { describe(key): EntryMetadata? }`
  (label / created / modified / attributes).
- **Labels + attributes on store** -- `LabeledVault.store(key, secret, label, attributes)`.
- **Interactive unlock / lock** (opt-in) -- `UnlockableVault { isLocked(); unlock(); lock() }`
  and `VaultConfig.unlockPolicy = IfLocked` / `unlockTimeoutMs`. Linux surfaces
  the Secret Service prompt and waits for `Completed`; Windows/macOS unlock with
  the login session (no-op). Default `Vault.open` never prompts.
- **Change-watch** -- `WatchableVault.onWatch(cb)` delivering `VaultChange` from
  Secret Service item signals on Linux (inert on Windows/macOS).
- **Tier migration** -- `MigratableVault.migrateTo(target, deleteAfter): MigrationReport`.
- **Custom collections** -- `VaultConfig.collection` + `Vault.collections(config)`.
  A real named collection on Linux; a logical key prefix on Windows/macOS.
- **macOS accessibility** -- `VaultConfig.accessibility` (`kSecAttrAccessible*`).

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
  - Linux/BSD -- Freedesktop Secret Service over `libdbus-1` (no runtime
    libsecret, no dbus-java).
  - Windows -- Credential Manager / DPAPI over `Advapi32`.
  - macOS -- Keychain Services over `Security.framework`.
- AES-256-GCM software-file fallback: versioned header, per-record nonce,
  key-bound AAD, verifier block, atomic writes. MachineBound (PBKDF2) and
  Passphrase (Argon2id) key derivation.
- Memory and None tiers.
- Per-operation and backend-selection timeouts; a locked or wedged keyring
  degrades instead of blocking. On a locked collection the backend declines to
  prompt and falls back.
- `storeString` / `retrieveString` that keep text secrets out of interned
  `String`s.
