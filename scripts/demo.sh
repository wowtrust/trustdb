#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/trustdb-demo.XXXXXX")
trustdb_bin="$demo_dir/trustdb"

cleanup() {
  rm -rf "$demo_dir"
}
trap cleanup EXIT HUP INT TERM

printf 'Building TrustDB...\n'
cd "$repo_dir"
go build -o "$trustdb_bin" ./cmd/trustdb

printf 'hello TrustDB\n' > "$demo_dir/original.txt"
"$trustdb_bin" keygen --out "$demo_dir" --prefix client >/dev/null
"$trustdb_bin" keygen --out "$demo_dir" --prefix server >/dev/null

"$trustdb_bin" claim-file \
  --file "$demo_dir/original.txt" \
  --private-key "$demo_dir/client.key" \
  --tenant demo \
  --client local-demo \
  --key-id client-key \
  --out "$demo_dir/original.tdclaim" >/dev/null

"$trustdb_bin" commit \
  --claim "$demo_dir/original.tdclaim" \
  --server-private-key "$demo_dir/server.key" \
  --client-public-key "$demo_dir/client.pub" \
  --wal "$demo_dir/wal" \
  --out "$demo_dir/original.tdproof" >/dev/null

printf '\n1/2 Verifying the original file (expected: valid)...\n'
"$trustdb_bin" verify \
  --file "$demo_dir/original.txt" \
  --proof "$demo_dir/original.tdproof" \
  --server-public-key "$demo_dir/server.pub" \
  --client-public-key "$demo_dir/client.pub"

cp "$demo_dir/original.txt" "$demo_dir/tampered.txt"
printf 'tampered\n' >> "$demo_dir/tampered.txt"

printf '\n2/2 Verifying a modified copy (expected: rejected)...\n'
if "$trustdb_bin" verify \
  --file "$demo_dir/tampered.txt" \
  --proof "$demo_dir/original.tdproof" \
  --server-public-key "$demo_dir/server.pub" \
  --client-public-key "$demo_dir/client.pub"; then
  printf 'ERROR: modified content was unexpectedly accepted.\n' >&2
  exit 1
fi

printf '\nDemo complete: TrustDB accepted the original and rejected the modified copy.\n'
