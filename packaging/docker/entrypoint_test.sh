#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
entrypoint="$repo_dir/packaging/docker/entrypoint.sh"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/trustdb-entrypoint-test.XXXXXX")

cleanup() {
  rm -rf "$test_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$test_dir/bin"
cat >"$test_dir/bin/trustdb" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$TRUSTDB_ENTRYPOINT_TEST_LOG"
out=
prefix=
is_keygen=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    keygen)
      is_keygen=1
      ;;
    --out)
      shift
      out="$1"
      ;;
    --prefix)
      shift
      prefix="$1"
      ;;
  esac
  shift
done
if [ "$is_keygen" -eq 1 ]; then
  : >"$out/$prefix.key"
  : >"$out/$prefix.pub"
fi
EOF
chmod 0755 "$test_dir/bin/trustdb"

run_entrypoint() {
  PATH="$test_dir/bin:$PATH" \
    TRUSTDB_CONTAINER_DATA_DIR="$test_dir/data" \
    TRUSTDB_CONFIG="$test_dir/config.yaml" \
    TRUSTDB_ENTRYPOINT_TEST_LOG="$test_dir/calls.log" \
    sh "$entrypoint" serve
}

if run_entrypoint >"$test_dir/no-secret.out" 2>"$test_dir/no-secret.err"; then
  echo "entrypoint accepted first-run generation without a passphrase source" >&2
  exit 1
fi
if ! grep -q "requires exactly one" "$test_dir/no-secret.err"; then
  echo "entrypoint did not explain the missing passphrase source" >&2
  exit 1
fi
if [ -e "$test_dir/calls.log" ]; then
  echo "entrypoint invoked trustdb before validating the passphrase source" >&2
  exit 1
fi

secret='entrypoint test passphrase must stay out of argv and logs'
TRUSTDB_DEV_KEY_PASSPHRASE="$secret" run_entrypoint >"$test_dir/success.out" 2>"$test_dir/success.err"
unset TRUSTDB_DEV_KEY_PASSPHRASE
if grep -R -q "$secret" "$test_dir/success.out" "$test_dir/success.err" "$test_dir/calls.log"; then
  echo "entrypoint exposed the passphrase in output or child arguments" >&2
  exit 1
fi
if [ "$(wc -l <"$test_dir/calls.log" | tr -d ' ')" -ne 3 ]; then
  echo "entrypoint did not generate both keys before serving" >&2
  exit 1
fi

rm -rf "$test_dir/data"
rm -f "$test_dir/calls.log"
passphrase_file="$test_dir/passphrase"
printf '%s\n' 'entrypoint file passphrase' >"$passphrase_file"
chmod 0600 "$passphrase_file"
TRUSTDB_DEV_KEY_PASSPHRASE_FILE="$passphrase_file" run_entrypoint >"$test_dir/file.out" 2>"$test_dir/file.err"
unset TRUSTDB_DEV_KEY_PASSPHRASE_FILE
if [ "$(wc -l <"$test_dir/calls.log" | tr -d ' ')" -ne 3 ]; then
  echo "entrypoint did not accept the secret-file contract" >&2
  exit 1
fi

printf 'entrypoint secret-source tests passed\n'
