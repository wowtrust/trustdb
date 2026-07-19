#!/bin/sh
set -eu

config_path="${TRUSTDB_CONFIG:-/etc/trustdb/config.yaml}"
key_dir="${TRUSTDB_CONTAINER_KEY_DIR:-/var/lib/trustdb/keys}"

generate_pair() {
  prefix="$1"
  if [ ! -e "$key_dir/$prefix.key" ] && [ ! -e "$key_dir/$prefix.pub" ]; then
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
  mkdir -p "$key_dir" /var/lib/trustdb/logs
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
