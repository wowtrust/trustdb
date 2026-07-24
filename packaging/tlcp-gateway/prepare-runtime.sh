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

if [ "${TLCP_PREPARE_DEADLINE_ACTIVE:-}" != "1" ]; then
  deadline=$(
    /usr/local/bin/trustdb-tlcp-profile timeout \
      --profile "$TLCP_PROFILE_FILE" \
      --lifecycle "$lifecycle"
  )
  TLCP_PREPARE_DEADLINE_ACTIVE=1
  export TLCP_PREPARE_DEADLINE_ACTIVE
  exec /usr/bin/timeout \
    --foreground \
    --signal=TERM \
    --kill-after=1s \
    "$deadline" \
    "$0" "$lifecycle"
fi
unset TLCP_PREPARE_DEADLINE_ACTIVE

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
