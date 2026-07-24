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

case "${1:-}" in
  startup|reload) lifecycle=$1 ;;
  *) fail "lifecycle argument must be startup or reload" ;;
esac

case "$TLCP_PROFILE_FILE" in
  /*) ;;
  *) fail "TLCP_PROFILE_FILE must be an absolute path" ;;
esac

configuration=/run/tlcp-gateway/nginx.conf
runtime_manifest=/run/tlcp-gateway/runtime-manifest.json
exec /usr/local/bin/trustdb-tlcp-profile activate-runtime \
  --profile "$TLCP_PROFILE_FILE" \
  --lifecycle "$lifecycle" \
  --expected-image-digest "$TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST" \
  --configuration "$configuration" \
  --runtime-manifest "$runtime_manifest" \
  --gateway /usr/local/sbin/tlcp-gateway \
  --gateway-prefix /run/tlcp-gateway
