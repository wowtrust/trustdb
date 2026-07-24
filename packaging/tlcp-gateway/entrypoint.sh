#!/bin/sh
set -eu

configuration=/run/tlcp-gateway/nginx.conf
/usr/local/bin/tlcp-gateway-prepare-runtime startup
exec /usr/local/sbin/tlcp-gateway -c "$configuration" -p /run/tlcp-gateway
