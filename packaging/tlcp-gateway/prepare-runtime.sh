#!/bin/sh
set -eu

fail() {
  printf 'TLCP gateway runtime preparation: %s\n' "$1" >&2
  exit 1
}

require_env() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || fail "$1 is required"
}

require_env TLCP_PROFILE_FILE
require_env TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST

case "$TLCP_PROFILE_FILE" in
  /*) ;;
  *) fail "TLCP_PROFILE_FILE must be an absolute path" ;;
esac

configuration=/run/tlcp-gateway/nginx.conf
runtime_manifest=/run/tlcp-gateway/runtime-manifest.json
next_configuration="${configuration}.next.$$"
next_manifest="${runtime_manifest}.next.$$"
trap 'rm -f "$next_configuration" "$next_manifest"' EXIT HUP INT TERM
umask 077

/usr/local/bin/trustdb-tlcp-profile prepare-runtime \
  --profile "$TLCP_PROFILE_FILE" \
  --expected-image-digest "$TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST" \
  --configuration "$next_configuration" \
  --runtime-manifest "$next_manifest"

/usr/local/sbin/tlcp-gateway \
  -t \
  -c "$next_configuration" \
  -p /run/tlcp-gateway

mv "$next_configuration" "$configuration"
mv "$next_manifest" "$runtime_manifest"
trap - EXIT HUP INT TERM
