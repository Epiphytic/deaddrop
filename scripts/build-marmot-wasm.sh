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

cargo build --locked -p marmot-wasm-probe --target wasm32-unknown-unknown
