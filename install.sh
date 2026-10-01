#!/bin/sh
# Installs the revefi-agent-analyzer binary for this machine from GitHub Releases.
#
#   curl -fsSL https://github.com/revefi/agent-analyzer/releases/latest/download/install.sh | sh
#
# REVEFI_VERSION=v0.1.0      install a specific release instead of the latest
# REVEFI_INSTALL_DIR=<dir>   install somewhere other than ~/.local/bin
# REVEFI_DOWNLOAD_URL=<url>  fetch the binary from a mirror (needs REVEFI_VERSION; checksums
#                            still come from GitHub)
# REVEFI_VERIFY=1            refuse to install unless the GitHub build attestation checks out
#                            (needs the gh CLI; it is checked whenever gh is installed)
set -eu

main() {
  repo="revefi/agent-analyzer"
  [ -n "${HOME:-}" ] || fail "HOME isn't set; set REVEFI_INSTALL_DIR to choose where to install."
  if [ "$(id -u)" = 0 ] && [ -z "${REVEFI_INSTALL_DIR:-}" ]; then
    fail "don't run this as root. Run it as yourself, or set REVEFI_INSTALL_DIR to install system-wide."
  fi
  dest="${REVEFI_INSTALL_DIR:-$HOME/.local/bin}"

  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) fail "this installer supports macOS and Linux. On Windows, download revefi-agent-analyzer-windows-x64.exe from https://github.com/$repo/releases, or run: npm install -g revefi-agent-analyzer" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=x64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) fail "no binary for $(uname -m). Install with npm instead: npm install -g revefi-agent-analyzer" ;;
  esac
  # A shell running under Rosetta reports x86_64 on Apple silicon.
  if [ "$os" = darwin ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then arch=arm64; fi
  if [ "$os" = linux ] && { [ -e "/lib/ld-musl-$(uname -m).so.1" ] || ldd --version 2>&1 | grep -qi musl; }; then
    fail "musl-based Linux (such as Alpine) isn't supported by the binary. Install with npm instead: npm install -g revefi-agent-analyzer"
  fi

  version="${REVEFI_VERSION:-latest}"
  case "$version" in latest | v*) ;; *) version="v$version" ;; esac
  if [ "$version" = latest ]; then
    # Resolve "latest" once, so the binary and its checksums come from the same release.
    url=$(fetch -o /dev/null -w '%{url_effective}' -I "https://github.com/$repo/releases/latest") ||
      fail "couldn't find the latest release of $repo"
    version="${url##*/}"
  fi
  releases="https://github.com/$repo/releases/download/$version"
  if [ -n "${REVEFI_DOWNLOAD_URL:-}" ]; then
    [ -n "${REVEFI_VERSION:-}" ] || fail "REVEFI_DOWNLOAD_URL needs REVEFI_VERSION, so the checksum can come from GitHub."
    base="$REVEFI_DOWNLOAD_URL"
  else
    base="$releases"
  fi

  asset="revefi-agent-analyzer-$os-$arch"
  mkdir -p "$dest"
  # Downloading next to the destination makes the final rename atomic.
  tmp=$(mktemp -d "$dest/.revefi-install.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT TERM

  echo "Downloading $asset ($version)..."
  fetch -o "$tmp/$asset" "$base/$asset" || fail "couldn't download $base/$asset"
  fetch -o "$tmp/SHA256SUMS" "$releases/SHA256SUMS" || fail "couldn't download $releases/SHA256SUMS"

  expected=$(awk -v f="$asset" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS")
  [ -n "$expected" ] || fail "SHA256SUMS has no entry for $asset"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
  else
    actual=$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')
  fi
  [ "$expected" = "$actual" ] || fail "checksum mismatch for $asset; nothing was installed. Try again, and report it if it persists."

  if command -v gh >/dev/null 2>&1; then
    gh attestation verify "$tmp/$asset" --repo "$repo" \
      --signer-workflow "$repo/.github/workflows/release.yml" >/dev/null 2>&1 ||
      fail "the build attestation for $asset didn't verify; nothing was installed."
    echo "Verified the build attestation."
  elif [ "${REVEFI_VERIFY:-}" = 1 ]; then
    fail "REVEFI_VERIFY=1 needs the GitHub CLI (gh) to check the build attestation."
  fi

  chmod 0755 "$tmp/$asset"
  installed=$("$tmp/$asset" --version) || fail "the downloaded binary doesn't run on this machine; nothing was installed."
  mv -f "$tmp/$asset" "$dest/revefi-agent-analyzer"
  echo "Installed revefi-agent-analyzer $installed to $dest/revefi-agent-analyzer"

  case ":$PATH:" in
    *":$dest:"*) ;;
    *) echo "Add $dest to your PATH to run it as revefi-agent-analyzer, for example: export PATH=\"$dest:\$PATH\"" ;;
  esac
}

fail() {
  echo "install.sh: $1" >&2
  exit 1
}

fetch() {
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --connect-timeout 15 "$@"
}

main "$@"
