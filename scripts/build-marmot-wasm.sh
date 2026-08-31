#!/usr/bin/env bash
set -euo pipefail
cargo build --locked -p marmot-wasm-probe --target wasm32-unknown-unknown
