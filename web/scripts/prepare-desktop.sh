#!/bin/sh
# Prepares what the desktop app bundles, from the repository root:
#   1. the native binfera engine (capabilities + Ghidra decompiler) as a Tauri sidecar,
#      named binfera-<target triple> as Tauri requires;
#   2. the capa rules, as the bundled `rules` resource.
# Run once, and again whenever the engine or the rules change. Pass --target <triple> to build
# for another platform than the host's (CI does this per OS).
set -eu
cd "$(dirname "$0")/../.."
target=""
if [ "${1:-}" = "--target" ]; then target="$2"; fi
triple="${target:-$(rustc -vV | sed -n 's/^host: //p')}"
ext=""
case "$triple" in *windows*) ext=".exe";; esac

# The native decompiler builds on Linux, macOS and Windows (MSVC), each on a host of its own kind.
features="--features decompiler"

if [ -n "$target" ]; then
  cargo build --release --locked -p binfera-cli $features --target "$target"
  built="target/$target/release/binfera$ext"
else
  cargo build --release --locked -p binfera-cli $features
  built="target/release/binfera$ext"
fi
mkdir -p web/src-tauri/binaries
cp "$built" "web/src-tauri/binaries/binfera-$triple$ext"

# Rules: BINFERA_RULES_DIR, ./rules, or (in a git worktree) the main checkout's rules.
rules=""
for c in "${BINFERA_RULES_DIR:-${CAPA_RULES_DIR:-}}" rules "$(pwd | sed -n 's|^\(.*\)/\.claude/worktrees/.*|\1/rules|p')"; do
  if [ -n "$c" ] && [ -d "$c/anti-analysis" ]; then rules="$c"; break; fi
done
[ -n "$rules" ] || { echo "rules not found: set BINFERA_RULES_DIR or run 'git submodule update --init rules'" >&2; exit 1; }
rm -rf web/src-tauri/resources/rules
mkdir -p web/src-tauri/resources
cp -R "$rules" web/src-tauri/resources/rules
rm -rf web/src-tauri/resources/rules/.git
# ASCII file names only. A macOS app is signed on APFS, but its DMG stores names in another Unicode
# form, so a name such as `use-process-doppelgänging.yml` breaks the app's signature seal. Rules are
# identified by their contents, not their file names.
node -e '
const fs = require("fs"), path = require("path");
const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).forEach(e => {
  const from = path.join(dir, e.name);
  const ascii = e.name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^\x20-\x7e]/g, "_");
  const to = path.join(dir, ascii);
  if (ascii !== e.name) { if (fs.existsSync(to)) throw new Error("name clash: " + to); fs.renameSync(from, to); }
  if (e.isDirectory()) walk(to);
});
walk(process.argv[1]);
' web/src-tauri/resources/rules
echo "sidecar: web/src-tauri/binaries/binfera-$triple$ext; rules from $rules"
