#!/bin/sh
# Installs parda: downloads the release for this machine, checks its SHA-256, and sets it up.
#   curl -fsSL https://raw.githubusercontent.com/sundarshahi/parda/main/install.sh | sh
# Pick a version with PARDA_VERSION=v0.1.0.
set -eu

repo="${PARDA_REPO:-sundarshahi/parda}"
version="${PARDA_VERSION:-latest}"

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-musl ;;
  *) echo "parda runs on macOS and Linux (WSL 2 works). Windows support is planned." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) echo "parda has no release for this CPU ($(uname -m)). Build it with: cargo install --git https://github.com/$repo" >&2; exit 1 ;;
esac

file="parda-$arch-$os.tar.gz"
if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi
base="${PARDA_BASE_URL:-$base}" # a mirror, or a local folder for testing

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading ${file}..."
curl -fsSL "$base/$file" -o "$tmp/$file"
curl -fsSL "$base/$file.sha256" -o "$tmp/$file.sha256"
if command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && shasum -a 256 -c "$file.sha256" >/dev/null)
else
  (cd "$tmp" && sha256sum -c "$file.sha256" >/dev/null)
fi || { echo "The download's checksum doesn't match. Nothing was installed." >&2; exit 1; }

tar -xzf "$tmp/$file" -C "$tmp"
"$tmp/parda" install
