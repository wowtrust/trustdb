#!/bin/sh
set -eu

fail() {
  printf 'TLCP gateway: %s\n' "$1" >&2
  exit 1
}

require_env() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || fail "$1 is required"
}

require_safe_token() {
  name=$1
  value=$2
  case "$value" in
    *[!A-Za-z0-9_./:@,=+-]*|'') fail "$name contains unsupported characters" ;;
  esac
}

require_safe_address() {
  name=$1
  value=$2
  case "$value" in
    *[!0-9A-Fa-f.:\[\]]*|'') fail "$name must be an explicit IP address and port" ;;
  esac
}

require_absolute_file() {
  name=$1
  value=$2
  require_safe_token "$name" "$value"
  case "$value" in
    /*) ;;
    *) fail "$name must be an absolute path" ;;
  esac
  [ -f "$value" ] || fail "$name is not a regular file"
}

public_key_sha256_from_certificate() {
  /opt/tongsuo/bin/openssl x509 -in "$1" -pubkey -noout |
    /opt/tongsuo/bin/openssl pkey -pubin -outform DER 2>/dev/null |
    /opt/tongsuo/bin/openssl dgst -sha256 -r |
    cut -d ' ' -f 1
}

public_key_sha256_from_private_key() {
  /opt/tongsuo/bin/openssl pkey -in "$1" -pubout -outform DER 2>/dev/null |
    /opt/tongsuo/bin/openssl dgst -sha256 -r |
    cut -d ' ' -f 1
}

validate_key_reference() {
  role=$1
  provider=$2
  reference=$3
  certificate=$4
  expected_fingerprint=$5

  require_safe_token "TLCP_${role}_KEY_REFERENCE" "$reference"
  case "$expected_fingerprint" in
    *[!0-9a-f]*|'') fail "TLCP_${role}_PUBLIC_KEY_SHA256 must be lowercase hexadecimal" ;;
  esac
  [ "${#expected_fingerprint}" -eq 64 ] ||
    fail "TLCP_${role}_PUBLIC_KEY_SHA256 must contain 64 hexadecimal characters"

  certificate_fingerprint=$(public_key_sha256_from_certificate "$certificate") ||
    fail "cannot derive the ${role} certificate public key"
  [ "$certificate_fingerprint" = "$expected_fingerprint" ] ||
    fail "${role} certificate public key does not match the validated profile fingerprint"

  case "$TLCP_ENVIRONMENT:$provider" in
    production:engine|production:pkcs11|production:sdf)
      case "$reference" in
        engine:*:*) ;;
        *) fail "production ${role} key reference must use Tengine's opaque engine:<id>:<key-id> form" ;;
      esac
      engine_value=${reference#engine:}
      engine_id=${engine_value%%:*}
      key_id=${engine_value#*:}
      [ -n "$engine_id" ] && [ -n "$key_id" ] ||
        fail "production ${role} engine id and key id must not be empty"
      case "$key_id" in
        *:*) fail "production ${role} key id must not contain a nested provider separator" ;;
      esac
      if [ "$provider" != engine ] && [ "$engine_id" != "$provider" ]; then
        fail "production ${role} engine id must match the $provider provider"
      fi
      ;;
    test:file)
      require_absolute_file "TLCP_${role}_KEY_REFERENCE" "$reference"
      private_fingerprint=$(public_key_sha256_from_private_key "$reference") ||
        fail "cannot derive the test-only ${role} private-key public component"
      [ "$private_fingerprint" = "$certificate_fingerprint" ] ||
        fail "test-only ${role} private key does not match its certificate"
      ;;
    *)
      fail "$provider is not allowed for ${role} keys in $TLCP_ENVIRONMENT"
      ;;
  esac
}

for name in \
  TLCP_ENVIRONMENT \
  TLCP_SERVER_NAME \
  TLCP_SERVER_SIGNING_CHAIN_FILE \
  TLCP_SERVER_ENCRYPTION_CHAIN_FILE \
  TLCP_CLIENT_CA_FILE \
  TLCP_CRL_BUNDLE_FILE \
  TLCP_SIGNING_KEY_PROVIDER \
  TLCP_SIGNING_KEY_REFERENCE \
  TLCP_SIGNING_PUBLIC_KEY_SHA256 \
  TLCP_ENCRYPTION_KEY_PROVIDER \
  TLCP_ENCRYPTION_KEY_REFERENCE \
  TLCP_ENCRYPTION_PUBLIC_KEY_SHA256 \
  TLCP_GATEWAY_HTTP_BIND \
  TLCP_GATEWAY_GRPC_BIND \
  TLCP_TRUSTDB_HTTP_UPSTREAM \
  TLCP_TRUSTDB_GRPC_UPSTREAM
do
  require_env "$name"
done

case "$TLCP_ENVIRONMENT" in
  production|test) ;;
  *) fail "TLCP_ENVIRONMENT must be production or test" ;;
esac

require_safe_token TLCP_SERVER_NAME "$TLCP_SERVER_NAME"
for name in \
  TLCP_SERVER_SIGNING_CHAIN_FILE \
  TLCP_SERVER_ENCRYPTION_CHAIN_FILE \
  TLCP_CLIENT_CA_FILE \
  TLCP_CRL_BUNDLE_FILE
do
  eval "value=\${$name}"
  require_absolute_file "$name" "$value"
done
for name in TLCP_GATEWAY_HTTP_BIND TLCP_GATEWAY_GRPC_BIND
do
  eval "value=\${$name}"
  require_safe_address "$name" "$value"
done
for name in TLCP_TRUSTDB_HTTP_UPSTREAM TLCP_TRUSTDB_GRPC_UPSTREAM
do
  eval "value=\${$name}"
  require_safe_address "$name" "$value"
  case "$value" in
    127.0.0.1:*) ;;
    *) fail "$name must bind TrustDB plaintext to 127.0.0.1" ;;
  esac
done

validate_key_reference \
  SIGNING \
  "$TLCP_SIGNING_KEY_PROVIDER" \
  "$TLCP_SIGNING_KEY_REFERENCE" \
  "$TLCP_SERVER_SIGNING_CHAIN_FILE" \
  "$TLCP_SIGNING_PUBLIC_KEY_SHA256"
validate_key_reference \
  ENCRYPTION \
  "$TLCP_ENCRYPTION_KEY_PROVIDER" \
  "$TLCP_ENCRYPTION_KEY_REFERENCE" \
  "$TLCP_SERVER_ENCRYPTION_CHAIN_FILE" \
  "$TLCP_ENCRYPTION_PUBLIC_KEY_SHA256"

[ "$TLCP_SIGNING_PUBLIC_KEY_SHA256" != "$TLCP_ENCRYPTION_PUBLIC_KEY_SHA256" ] ||
  fail "TLCP signing and encryption keys must be distinct"
[ "$TLCP_SIGNING_KEY_REFERENCE" != "$TLCP_ENCRYPTION_KEY_REFERENCE" ] ||
  fail "TLCP signing and encryption key references must be distinct"

umask 077
config_tmp="${TLCP_CONFIG_FILE}.tmp.$$"
trap 'rm -f "$config_tmp"' EXIT HUP INT TERM
cat >"$config_tmp" <<EOF
worker_processes auto;
daemon off;
pid /run/tlcp-gateway/tlcp-gateway.pid;
error_log stderr info;

events {
    worker_connections 4096;
}

http {
    include /opt/tlcp-gateway/conf/mime.types;
    default_type application/octet-stream;
    access_log /dev/stdout;
    server_tokens off;

    server {
        listen $TLCP_GATEWAY_HTTP_BIND ssl http2;
        server_name $TLCP_SERVER_NAME;
        enable_ntls on;
        # Tengine initializes its ordinary TLS context from this directive too.
        # The RSA suite is only an initialization sentinel: this server has no
        # ordinary TLS certificate, while NTLS can negotiate only the SM suite.
        ssl_ciphers ECDHE-SM2-SM4-GCM-SM3:ECDHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers on;
        ssl_sign_certificate $TLCP_SERVER_SIGNING_CHAIN_FILE;
        ssl_sign_certificate_key $TLCP_SIGNING_KEY_REFERENCE;
        ssl_enc_certificate $TLCP_SERVER_ENCRYPTION_CHAIN_FILE;
        ssl_enc_certificate_key $TLCP_ENCRYPTION_KEY_REFERENCE;
        ssl_client_certificate $TLCP_CLIENT_CA_FILE;
        ssl_crl $TLCP_CRL_BUNDLE_FILE;
        ssl_verify_client on;
        ssl_verify_depth 8;

        location / {
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-Proto tlcp;
            proxy_pass http://$TLCP_TRUSTDB_HTTP_UPSTREAM;
        }
    }

    server {
        listen $TLCP_GATEWAY_GRPC_BIND ssl http2;
        server_name $TLCP_SERVER_NAME;
        enable_ntls on;
        # See the HTTP listener comment above. Integration tests require
        # ordinary TLS and every other NTLS cipher to fail.
        ssl_ciphers ECDHE-SM2-SM4-GCM-SM3:ECDHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers on;
        ssl_sign_certificate $TLCP_SERVER_SIGNING_CHAIN_FILE;
        ssl_sign_certificate_key $TLCP_SIGNING_KEY_REFERENCE;
        ssl_enc_certificate $TLCP_SERVER_ENCRYPTION_CHAIN_FILE;
        ssl_enc_certificate_key $TLCP_ENCRYPTION_KEY_REFERENCE;
        ssl_client_certificate $TLCP_CLIENT_CA_FILE;
        ssl_crl $TLCP_CRL_BUNDLE_FILE;
        ssl_verify_client on;
        ssl_verify_depth 8;

        location / {
            grpc_pass grpc://$TLCP_TRUSTDB_GRPC_UPSTREAM;
        }
    }
}
EOF

mv "$config_tmp" "$TLCP_CONFIG_FILE"
trap - EXIT HUP INT TERM
/usr/local/sbin/tlcp-gateway -t -c "$TLCP_CONFIG_FILE" -p /run/tlcp-gateway
exec /usr/local/sbin/tlcp-gateway -c "$TLCP_CONFIG_FILE" -p /run/tlcp-gateway
