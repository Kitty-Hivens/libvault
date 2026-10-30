#!/bin/sh
# Run a command against a disposable Secret Service: a private session bus and a
# gnome-keyring holding a throwaway login keyring, unlocked with a fixed
# password. Nothing reaches the user's own keyring, which the Secret Service
# tests would otherwise lock.
#
# Usage: with-secret-service.sh <command> [args...]
#
# The runtime directory sits under the real one because a Unix socket path
# stops at 108 bytes, and gnome-keyring puts its control socket there.
set -eu

base="${XDG_RUNTIME_DIR:-/tmp}"
dir=$(mktemp -d -p "$base" lvss.XXXXXX)
trap 'rm -rf "$dir"' EXIT
export XDG_RUNTIME_DIR="$dir" XDG_DATA_HOME="$dir/data" XDG_CONFIG_HOME="$dir/config"
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"

dbus-run-session -- sh -euc '
  printf test | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  # Through a client that knows nothing of this library, so a service that did
  # not come up fails here rather than as a test that quietly fell back.
  printf ready | secret-tool store --label=libvault-ci libvault-ci ready
  test "$(secret-tool lookup libvault-ci ready)" = ready
  "$@"
' sh "$@"
