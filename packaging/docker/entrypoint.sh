#!/bin/sh
set -eu

config_path="${TRUSTDB_CONFIG:-/etc/trustdb/config.yaml}"
data_dir="${TRUSTDB_CONTAINER_DATA_DIR:-/var/lib/trustdb}"
key_dir="${TRUSTDB_CONTAINER_KEY_DIR:-$data_dir/keys}"

require_development_kek() {
  has_value=0
  has_file=0
  if [ "${TRUSTDB_DEV_KEY_PASSPHRASE+x}" = x ]; then
    has_value=1
  fi
  if [ "${TRUSTDB_DEV_KEY_PASSPHRASE_FILE+x}" = x ]; then
    has_file=1
  fi
  if [ "$has_value" -eq "$has_file" ]; then
    echo "TrustDB first-run key generation requires exactly one of TRUSTDB_DEV_KEY_PASSPHRASE or TRUSTDB_DEV_KEY_PASSPHRASE_FILE" >&2
    echo "Mount an owner-only Docker/Kubernetes secret outside $key_dir; no KEK is written into the data volume" >&2
    exit 1
  fi
  if [ "$has_file" -eq 1 ] && [ ! -f "$TRUSTDB_DEV_KEY_PASSPHRASE_FILE" ]; then
    echo "TrustDB development passphrase secret file is missing or not a regular file" >&2
    exit 1
  fi
}

generate_pair() {
  prefix="$1"
  if [ ! -e "$key_dir/$prefix.key" ] && [ ! -e "$key_dir/$prefix.pub" ]; then
    require_development_kek
    trustdb --config "$config_path" keygen --out "$key_dir" --prefix "$prefix" >/dev/null
    echo "TrustDB generated a first-run $prefix key pair in $key_dir" >&2
    return
  fi
  if [ ! -f "$key_dir/$prefix.key" ] || [ ! -f "$key_dir/$prefix.pub" ]; then
    echo "TrustDB refuses to replace an incomplete $prefix key pair in $key_dir" >&2
    exit 1
  fi
}

if [ "$#" -eq 0 ]; then
  set -- serve
fi

if [ "$1" = "serve" ]; then
  mkdir -p "$key_dir" "$data_dir/logs"
  generate_pair server
  generate_pair client
  exec trustdb --config "$config_path" "$@"
fi

if [ "${1#-}" != "$1" ]; then
  set -- trustdb "$@"
fi

if [ "$1" = "trustdb" ]; then
  shift
fi
exec trustdb --config "$config_path" "$@"
