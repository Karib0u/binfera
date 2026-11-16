#!/bin/sh
# Installs the binfera command-line tool from a GitHub release (macOS and Linux).
#
#   curl -fsSL https://binfera.io/install.sh | sh
#
# It downloads the archive for this machine, checks it against the release's SHA256SUMS, and puts
# the `binfera` binary in $BINFERA_HOME/bin (default ~/.binfera/bin). The capability rules are inside
# the binary, so nothing else is installed. Nothing outside $BINFERA_HOME is touched: add the
# folder to your PATH as the last line says.
#
# BINFERA_VERSION  a release tag such as v1.0.0 (default: the latest release)
# BINFERA_HOME     where to install (default: ~/.binfera)
# BINFERA_BASE_URL where release files are downloaded from (default: the GitHub release; for testing)
# BINFERA_API_URL  the releases list used to find the latest version (for testing)
set -eu

repo="Karib0u/binfera"
home="${BINFERA_HOME:-$HOME/.binfera}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need curl
need tar

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  target="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64|Linux-arm64) target="aarch64-unknown-linux-gnu" ;;
  Darwin-arm64)  target="aarch64-apple-darwin" ;;
  Darwin-x86_64) target="x86_64-apple-darwin" ;;
  *) die "no prebuilt binfera for $(uname -s) $(uname -m); build it from source (see the README)" ;;
esac

version="${BINFERA_VERSION:-}"
if [ -z "$version" ]; then
  # Not GitHub's "latest release": the desktop app is released under `desktop-v*` tags, can become
  # the latest, and carries no command-line archives. Take the newest release tagged `v<number>`.
  api="${BINFERA_API_URL:-https://api.github.com/repos/$repo/releases?per_page=50}"
  version="$(curl -fsSL "$api" | tr ',' '\n' | sed -n 's/.*"tag_name": *"\(v[0-9][^"]*\)".*/\1/p' | head -1)"
  [ -n "$version" ] || die "could not find a command-line release of binfera"
fi
base="${BINFERA_BASE_URL:-https://github.com/$repo/releases/download/$version}"
name="binfera-$version-$target"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Downloading binfera $version for $target"
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || die "could not download $base/$name.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "could not download the checksums"

expected="$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
[ -n "$expected" ] || die "$name.tar.gz is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$name.tar.gz" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $name.tar.gz: expected $expected, got $actual"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$home/bin"
cp "$tmp/$name/binfera" "$home/bin/binfera"
chmod +x "$home/bin/binfera"

say "Installed $("$home/bin/binfera" --version) to $home/bin/binfera"
case ":$PATH:" in
  *":$home/bin:"*) ;;
  *) say "Add it to your PATH:  export PATH=\"$home/bin:\$PATH\"" ;;
esac
say "Next: claude mcp add --scope user binfera -- $home/bin/binfera mcp"
