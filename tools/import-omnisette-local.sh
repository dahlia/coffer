#!/usr/bin/env bash
set -euo pipefail

# This opt-in maintainer tool is deliberately outside `mise run check`: it
# fetches one immutable upstream commit to reproduce the checked-in MPL patch.
repository_root=$(git rev-parse --show-toplevel)
upstream_repository=https://github.com/SideStore/apple-private-apis.git
upstream_commit=03beb1aa42991ccdad6214dee77e72282bef461f
upstream_tree=7ef39962ce9a4f041ce1ad6f4915ea2e532a3ee3
archive_sha256=bb1154bb7d2af7a9b38a223a03d4e807694ec97ca0390fcca5be542d2cd51600
patch_sha256=e27436272e0dcb99255d1da7c00934ab50e1f33990ae62a504fbf20f73d62857
temporary_root=$(mktemp -d -t coffer-omnisette-import.XXXXXX)
trap 'rm -rf -- "$temporary_root"' EXIT

checkout=$temporary_root/upstream
raw=$temporary_root/raw
patched=$temporary_root/patched
mkdir -p "$raw" "$patched/src"
git init --quiet "$checkout"
git -C "$checkout" remote add origin "$upstream_repository"
git -C "$checkout" fetch --quiet --depth=1 origin "$upstream_commit"
test "$(git -C "$checkout" rev-parse FETCH_HEAD)" = "$upstream_commit"
test "$(git -C "$checkout" rev-parse 'FETCH_HEAD^{tree}')" = "$upstream_tree"

verify_stream_hash() {
  local expected=$1
  local actual
  actual=$(sha256sum)
  actual=${actual%% *}
  test "$actual" = "$expected"
}

verify_file_hash() {
  local path=$1
  local expected=$2
  local actual
  actual=$(sha256sum "$path")
  actual=${actual%% *}
  test "$actual" = "$expected"
}

git -C "$checkout" show FETCH_HEAD:LICENSE |
  verify_stream_hash 1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5
git -C "$checkout" show FETCH_HEAD:omnisette/Cargo.toml |
  verify_stream_hash 24b20eb7e8e7070b6c62adfadf56c8fbe1668ac91c23d2e7e466911e93e65833
git -C "$checkout" show FETCH_HEAD:omnisette/src/lib.rs |
  verify_stream_hash dc138772d9f680d48140b25c7e8097ef09ba3fc0aa1dcf91ee2cb8f444f87aa1
git -C "$checkout" show FETCH_HEAD:omnisette/src/adi_proxy.rs |
  verify_stream_hash 0bf29dbc2488d210423db82f0454482bd681f7a5d8e7537c20666dfed1941b11
git -C "$checkout" show FETCH_HEAD:omnisette/src/anisette_headers_provider.rs |
  verify_stream_hash ac722a884cbc0134902960bf11eb044e256cff7f3b008430704090ba972dd149

selected=(
  LICENSE
  omnisette/Cargo.toml
  omnisette/src/lib.rs
  omnisette/src/adi_proxy.rs
  omnisette/src/anisette_headers_provider.rs
)
git -C "$checkout" archive --format=tar FETCH_HEAD "${selected[@]}" |
  verify_stream_hash "$archive_sha256"
git -C "$checkout" archive --format=tar FETCH_HEAD "${selected[@]}" |
  tar -xf - -C "$raw"

mv "$raw/LICENSE" "$patched/LICENSE"
mv "$raw/omnisette/Cargo.toml" "$patched/Cargo.toml"
mv "$raw/omnisette/src/lib.rs" "$patched/src/lib.rs"
mv "$raw/omnisette/src/adi_proxy.rs" "$patched/src/adi_proxy.rs"
mv "$raw/omnisette/src/anisette_headers_provider.rs" \
  "$patched/src/anisette_headers_provider.rs"

patch=$repository_root/tools/omnisette-local.patch
verify_file_hash "$patch" "$patch_sha256"
git init --quiet "$patched"
git -C "$patched" apply --check "$patch"
git -C "$patched" apply "$patch"

vendor=$repository_root/crates/omnisette-local
for relative in Cargo.toml LICENSE src/lib.rs src/adi_proxy.rs \
  src/anisette_headers_provider.rs; do
  cmp "$patched/$relative" "$vendor/$relative"
done

printf '%s\n' "omnisette-local reproduced from $upstream_commit"
