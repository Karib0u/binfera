#!/bin/sh
# Builds the binfera CLI (capabilities + native Ghidra decompiler) for the browser:
# WebAssembly via Emscripten, then copies the module next to the UI sources.
# Needs: `rustup target add wasm32-unknown-emscripten` and `emcc` (brew install emscripten).
set -eu
cd "$(dirname "$0")/../.."
command -v emcc >/dev/null || { echo "emcc not found: install Emscripten (brew install emscripten)" >&2; exit 1; }
cargo build --profile wasm --locked -p binfera-cli --features decompiler --target wasm32-unknown-emscripten
out=target/wasm32-unknown-emscripten/wasm
mkdir -p web/src/wasm
# Cloudflare Workers refuses a static asset over 25 MiB, which only shows at deploy time otherwise.
size=$(wc -c < "$out/binfera.wasm")
echo "binfera.wasm: $size bytes (asset limit: 26214400 bytes)"
if [ "$size" -gt 26214400 ]; then
  echo "binfera.wasm is $size bytes, over the 25 MiB (26214400 bytes) a deployed asset can be" >&2
  exit 1
fi
if [ "$size" -ge 25690112 ]; then
  message="binfera.wasm is $size bytes, at least 98% of the 25 MiB asset limit"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::warning::$message"
  else
    echo "warning: $message" >&2
  fi
fi
cp "$out/binfera.js" "$out/binfera.wasm" web/src/wasm/
# Signature databases and Function ID packs are not embedded in the wasm build: the page fetches
# them (only the Function ID pack for the sample's architecture) from public/sigs.
mkdir -p web/public/sigs
cp binfera/sigs/*.sig web/public/sigs/
# Remove packs left by older builds so they are not deployed alongside the compressed assets.
rm -f web/public/sigs/fid-*.pack
for arch in x64 x86; do
  gzip -9 -n -c "binfera/sigs/fid-$arch.pack" > "web/public/sigs/fid-$arch.packz"
done
ls -lh web/src/wasm web/public/sigs
