# Changelog

All notable changes to libvault are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
