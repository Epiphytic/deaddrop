#!/usr/bin/env bash
set -euo pipefail

compiler_supports_wasm32() {
  local compiler="$1"
  case "$("$compiler" --print-targets 2>/dev/null)" in
    *wasm32*) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ -n "${CC_wasm32_unknown_unknown:-}" ]]; then
  if ! compiler_supports_wasm32 "$CC_wasm32_unknown_unknown"; then
    echo "error: CC_wasm32_unknown_unknown does not name a WebAssembly-capable compiler: $CC_wasm32_unknown_unknown" >&2
    exit 1
  fi
elif [[ "$(uname -s)" == "Darwin" ]]; then
  default_compiler="${CC:-cc}"
  if ! compiler_supports_wasm32 "$default_compiler"; then
    for candidate in \
      /opt/homebrew/opt/llvm/bin/clang \
      /usr/local/opt/llvm/bin/clang
    do
      if [[ -x "$candidate" ]] && compiler_supports_wasm32 "$candidate"; then
        export CC_wasm32_unknown_unknown="$candidate"
        break
      fi
    done
  fi

  if ! compiler_supports_wasm32 "${CC_wasm32_unknown_unknown:-$default_compiler}"; then
    echo "error: no WebAssembly-capable C compiler found; set CC_wasm32_unknown_unknown or install Homebrew LLVM with 'brew install llvm'" >&2
    exit 1
  fi
fi

if [[ -n "${CC_wasm32_unknown_unknown:-}" ]]; then
  echo "marmot wasm probe: using WebAssembly C compiler $CC_wasm32_unknown_unknown" >&2
fi

# Keep the portability probe independent of inherited flags that can re-enable
# unsupported cfgs such as tokio_unstable through either Cargo environment channel.
env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
  cargo build --locked -p marmot-wasm-probe --target wasm32-unknown-unknown

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack is required for the browser runtime gate" >&2
  exit 1
fi

env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
  wasm-pack build crates/marmot-wasm-probe \
    --target web \
    --out-dir ../../artifacts/feasibility/marmot-wasm

env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
  wasm-pack test --headless --chrome crates/marmot-wasm-probe

wasm_artifact="artifacts/feasibility/marmot-wasm/marmot_wasm_probe_bg.wasm"
uncompressed_bytes="$(wc -c < "$wasm_artifact" | tr -d ' ')"
gzip_bytes="$(gzip -c "$wasm_artifact" | wc -c | tr -d ' ')"
size_artifact="artifacts/feasibility/marmot-wasm-size.json"
{
  echo '{'
  echo '  "informational": true,'
  echo "  \"uncompressed_bytes\": $uncompressed_bytes,"
  echo "  \"gzip_bytes\": $gzip_bytes"
  echo '}'
} > "$size_artifact"

echo "marmot wasm probe: $uncompressed_bytes bytes ($gzip_bytes bytes gzip)" >&2
