#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${BUILD_DATE:?BUILD_DATE is required}"
: "${TARGET_ARCH:?TARGET_ARCH is required}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

cd "$GITHUB_WORKSPACE/clients/desktop"
go run github.com/wailsapp/wails/v2/cmd/wails@v2.12.0 build \
  -clean \
  -platform "darwin/$TARGET_ARCH" \
  -trimpath \
  -ldflags "-s -w -X main.desktopVersion=$VERSION -X main.desktopCommit=$GITHUB_SHA -X main.desktopDate=$BUILD_DATE"

app_path="$PWD/build/bin/trustdb.app"
if [ ! -d "$app_path" ]; then
  echo "::error::Wails did not produce $app_path"
  exit 1
fi

cert_dir="$RUNNER_TEMP/trustdb-cert"
keychain="$RUNNER_TEMP/trustdb-signing.keychain-db"
output_dir="$PWD/release-output"
mkdir -p "$cert_dir" "$output_dir"
password="$(openssl rand -hex 24)"
original_keychains=()
while IFS= read -r original_keychain; do
  original_keychains+=("$original_keychain")
done < <(security list-keychains -d user | sed -e 's/^[[:space:]]*"//' -e 's/"$//')
cleanup() {
  security list-keychains -d user -s "${original_keychains[@]}" >/dev/null 2>&1 || true
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  find "$cert_dir" -type f -delete >/dev/null 2>&1 || true
  rmdir "$cert_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cat > "$cert_dir/openssl.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = extensions
prompt = no
[dn]
CN = TrustDB Community Self-Signed $VERSION
O = TrustDB Community
[extensions]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -x509 -newkey rsa:3072 -nodes \
  -days 397 \
  -config "$cert_dir/openssl.cnf" \
  -keyout "$cert_dir/signing.key" \
  -out "$cert_dir/signing.pem"
openssl pkcs12 -export \
  -inkey "$cert_dir/signing.key" \
  -in "$cert_dir/signing.pem" \
  -name "TrustDB Community Self-Signed $VERSION" \
  -passout "pass:$password" \
  -out "$cert_dir/signing.p12"

package="trustdb-desktop-$VERSION-darwin-$TARGET_ARCH"
openssl x509 -in "$cert_dir/signing.pem" -outform DER \
  -out "$output_dir/$package.cer"
openssl x509 -in "$cert_dir/signing.pem" -noout -sha256 -fingerprint \
  > "$output_dir/$package-certificate.txt"

security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$cert_dir/signing.p12" \
  -k "$keychain" -P "$password" -T /usr/bin/codesign
security list-keychains -d user -s "$keychain" "${original_keychains[@]}"
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
identity="$(security find-certificate -a -Z -c "TrustDB Community Self-Signed $VERSION" "$keychain" | awk '/SHA-1 hash:/ {print $3; exit}')"
if [ -z "$identity" ]; then
  echo "::error::self-signed code-signing certificate was not created"
  exit 1
fi

codesign --force --deep --options runtime --timestamp=none \
  --keychain "$keychain" --sign "$identity" "$app_path"
codesign --verify --deep --strict --verbose=2 "$app_path"
codesign -dvvv "$app_path" 2>&1 | grep -F "Authority=TrustDB Community Self-Signed $VERSION"

stage="$RUNNER_TEMP/$package"
mkdir -p "$stage"
cp -R "$app_path" "$stage/TrustDB Desktop.app"
cp "$output_dir/$package.cer" "$stage/TrustDB-self-signed.cer"
cp "$output_dir/$package-certificate.txt" "$stage/CERTIFICATE_SHA256.txt"
cp "$GITHUB_WORKSPACE/packaging/SELF_SIGNED_CLIENTS.md" "$stage/SELF_SIGNED_CLIENTS.md"

ditto -c -k --sequesterRsrc --keepParent "$stage" "$output_dir/$package.zip"
ln -s /Applications "$stage/Applications"
hdiutil create -quiet -fs HFS+ -volname "TrustDB Desktop" \
  -srcfolder "$stage" "$output_dir/$package.dmg"
codesign --force --timestamp=none --keychain "$keychain" \
  --sign "$identity" "$output_dir/$package.dmg"
codesign --verify --strict --verbose=2 "$output_dir/$package.dmg"
