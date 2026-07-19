#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${BUILD_DATE:?BUILD_DATE is required}"
: "${TARGET_OS:?TARGET_OS is required}"
: "${TARGET_ARCH:?TARGET_ARCH is required}"
: "${CGO_ENABLED:?CGO_ENABLED is required}"

exe_suffix="${EXE_SUFFIX:-}"
archive_kind="${ARCHIVE_KIND:-tar.gz}"
package="trustdb-$VERSION-$TARGET_OS-$TARGET_ARCH"
output="release-bin/trustdb$exe_suffix"
root="release-stage/$package"

actual_os="$(go env GOOS)"
actual_arch="$(go env GOARCH)"
if [ "$actual_os" != "$TARGET_OS" ] || [ "$actual_arch" != "$TARGET_ARCH" ]; then
  echo "native runner mismatch: got $actual_os/$actual_arch, expected $TARGET_OS/$TARGET_ARCH" >&2
  exit 1
fi

mkdir -p release-bin "$root/bin" "$root/admin" "$root/config" release-output
go build -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$GITHUB_SHA -X main.date=$BUILD_DATE" \
  -o "$output" ./cmd/trustdb

"$output" version | tee release-bin/version.json
grep -F "\"version\":\"$VERSION\"" release-bin/version.json
grep -F "\"os\":\"$TARGET_OS\"" release-bin/version.json
grep -F "\"arch\":\"$TARGET_ARCH\"" release-bin/version.json

cp "$output" "$root/bin/"
cp release-bin/version.json "$root/BUILD_INFO.json"
cp -R release-admin/. "$root/admin/"
cp configs/production.yaml "$root/config/production.yaml"
cp configs/docker.yaml "$root/config/docker.yaml"
cp packaging/RELEASE_PACKAGE.md "$root/README.md"
cp LICENSE "$root/LICENSE"

if [ "$archive_kind" = "zip" ]; then
  powershell -NoProfile -Command \
    "Compress-Archive -Path 'release-stage/$package' -DestinationPath 'release-output/$package.zip' -CompressionLevel Optimal"
else
  tar -C release-stage -czf "release-output/$package.tar.gz" "$package"
fi
