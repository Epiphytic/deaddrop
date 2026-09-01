#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
source_repo="https://github.com/ethereum/tor-js.git"
source_rev="dfa2096ec2067b063e873525f7ac6beaba5be966"
install_root="$repo_root/artifacts/tools/tor-js-gateway"
binary="$install_root/bin/tor-js-gateway"
stamp="$install_root/.source-rev"
patch_file="$repo_root/patches/tor-js-gateway-loopback.patch"
patch_sha="$(shasum -a 256 "$patch_file" | awk '{print $1}')"

if [[ -x "$binary" && -f "$stamp" ]]; then
  installed_source="$(sed -n 's/^source_rev=//p' "$stamp")"
  installed_patch="$(sed -n 's/^patch_sha256=//p' "$stamp")"
  installed_binary="$(sed -n 's/^binary_sha256=//p' "$stamp")"
  actual_binary="$(shasum -a 256 "$binary" | awk '{print $1}')"
  if [[ "$installed_source" == "$source_rev" &&
        "$installed_patch" == "$patch_sha" &&
        "$installed_binary" == "$actual_binary" ]]; then
    exit 0
  fi
fi

checkout="$(mktemp -d)"
cleanup() { rm -rf "$checkout"; }
trap cleanup EXIT

git -C "$checkout" init --quiet
git -C "$checkout" remote add origin "$source_repo"
git -C "$checkout" fetch --quiet --depth 1 origin "$source_rev"
checked_out="$(git -C "$checkout" rev-parse FETCH_HEAD)"
if [[ "$checked_out" != "$source_rev" ]]; then
  echo "gateway source mismatch: expected $source_rev, got $checked_out" >&2
  exit 1
fi
git -C "$checkout" checkout --quiet --detach FETCH_HEAD
git -C "$checkout" apply --check "$patch_file"
git -C "$checkout" apply "$patch_file"

CARGO_TARGET_DIR="$install_root/build-cache" cargo install \
  --path "$checkout/crates/tor-js-gateway" \
  --locked \
  --root "$install_root"
binary_sha="$(shasum -a 256 "$binary" | awk '{print $1}')"
{
  printf 'source_rev=%s\n' "$source_rev"
  printf 'patch_sha256=%s\n' "$patch_sha"
  printf 'binary_sha256=%s\n' "$binary_sha"
} > "$stamp"
