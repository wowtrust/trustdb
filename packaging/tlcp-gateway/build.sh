#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
baseline="$root/packaging/tlcp-gateway/baseline.json"
dockerfile="$root/packaging/tlcp-gateway/Dockerfile"
output_dir=${OUTPUT_DIR:-"$root/dist/tlcp-gateway"}
platform=${PLATFORM:-linux/amd64}
platform_id=$(printf '%s' "$platform" | tr / -)
source_date_epoch=1702545703
syft_image='docker.io/anchore/syft:v1.38.2@sha256:63a159108794114992136692c92155c7694f259aca814a92c187a4e025754b00'
buildx_version='v0.35.0'
buildkit_image='docker.io/moby/buildkit:v0.31.2@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec'
build_progress=${BUILDKIT_PROGRESS:-plain}

case "$platform" in
  linux/amd64|linux/arm64) ;;
  *)
    printf 'unsupported TLCP gateway platform: %s\n' "$platform" >&2
    exit 1
    ;;
esac

actual_buildx_version=$(docker buildx version | awk 'NR == 1 { print $2 }')
if [ "$actual_buildx_version" != "$buildx_version" ]; then
  printf 'TLCP gateway requires Docker Buildx %s, got %s\n' \
    "$buildx_version" "$actual_buildx_version" >&2
  exit 1
fi
builder_details=$(docker buildx inspect --bootstrap)
case "$builder_details" in
  *"Driver:"*"docker-container"*) ;;
  *)
    printf 'TLCP gateway requires the docker-container Buildx driver\n' >&2
    exit 1
    ;;
esac
case "$builder_details" in
  *"$buildkit_image"*) ;;
  *)
    printf 'TLCP gateway builder does not use the reviewed BuildKit image\n' >&2
    exit 1
    ;;
esac
case "$builder_details" in
  *"BuildKit version:"*"v0.31.2"*) ;;
  *)
    printf 'TLCP gateway builder does not run the reviewed BuildKit release\n' >&2
    exit 1
    ;;
esac

mkdir -p "$output_dir"
work=$(mktemp -d "$output_dir/.build.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

build_image() {
  destination=$1
  metadata=$2
  SOURCE_DATE_EPOCH=$source_date_epoch docker buildx build \
    --file "$dockerfile" \
    --metadata-file "$metadata" \
    --no-cache \
    --output "type=oci,dest=$destination,rewrite-timestamp=true" \
    --platform "$platform" \
    --progress "$build_progress" \
    --provenance=false \
    "$root"
}

build_image "$work/gateway-first.oci.tar" "$work/metadata-first.json"
build_image "$work/gateway-second.oci.tar" "$work/metadata-second.json"
if ! cmp -s "$work/gateway-first.oci.tar" "$work/gateway-second.oci.tar"; then
  printf 'TLCP gateway clean rebuild produced a different OCI archive\n' >&2
  exit 1
fi

image_digest=$(
  cd "$root"
  go run ./cmd/trustdb-tlcp-build-record oci-digest \
    --oci-archive "$work/gateway-first.oci.tar" \
    --platform "$platform"
)

docker run --rm \
  --env SYFT_CHECK_FOR_APP_UPDATE=false \
  --volume "$work:/work" \
  "$syft_image" \
  "oci-archive:/work/gateway-first.oci.tar" \
  -o spdx-json=/work/gateway.sbom.raw.json

(
  cd "$root"
  go run ./cmd/trustdb-tlcp-build-record normalize-sbom \
    --baseline "$baseline" \
    --image-digest "$image_digest" \
    --input "$work/gateway.sbom.raw.json" \
    --output "$work/gateway.sbom.spdx.json"
  go run ./cmd/trustdb-tlcp-build-record record \
    --baseline "$baseline" \
    --checksum-output "$work/gateway.build-record.json.sha256" \
    --oci-archive "$work/gateway-first.oci.tar" \
    --output "$work/gateway.build-record.json" \
    --platform "$platform" \
    --sbom "$work/gateway.sbom.spdx.json"
  go run ./cmd/trustdb-tlcp-build-record verify \
    --baseline "$baseline" \
    --oci-archive "$work/gateway-first.oci.tar" \
    --platform "$platform" \
    --record "$work/gateway.build-record.json" \
    --record-sha256 "$work/gateway.build-record.json.sha256" \
    --sbom "$work/gateway.sbom.spdx.json"
)

docker load --input "$work/gateway-first.oci.tar" >/dev/null
docker run --rm --platform "$platform" --entrypoint /bin/sh "$image_digest" \
  -c 'cat /usr/share/trustdb/tlcp-gateway/build-baseline.json' \
  >"$work/baseline-from-image.json"
if ! cmp -s "$baseline" "$work/baseline-from-image.json"; then
  printf 'TLCP gateway image does not contain the reviewed build baseline\n' >&2
  exit 1
fi
docker run --rm --platform "$platform" --entrypoint /bin/sh "$image_digest" -c '
  set -eu
  fail() {
    printf "TLCP gateway runtime check failed: %s\n" "$1" >&2
    exit 1
  }
  [ "$(id -u)" = 10001 ] || fail "UID is not 10001"
  [ "$(id -g)" = 10001 ] || fail "GID is not 10001"
  [ "$(getent passwd trustdb | cut -d: -f3-4)" = "10001:10001" ] ||
    fail "trustdb runtime identity is missing"
  [ -w /run/tlcp-gateway ] || fail "runtime directory is not writable"
  [ ! -w /etc/trustdb/tlcp ] || fail "configuration directory is writable"
  [ -x /usr/local/bin/trustdb-tlcp-profile ] || fail "strict profile validator is missing"
  [ -x /usr/local/bin/trustdb-tlcp-readiness ] || fail "credentialed readiness probe is missing"
  [ -x /usr/local/bin/tlcp-gateway-prepare-runtime ] ||
    fail "validated runtime activation helper is missing"
  tengine_license=$(sha256sum /usr/share/licenses/trustdb-tlcp-gateway/Tengine-LICENSE | cut -d " " -f1)
  [ "$tengine_license" = "8444037a744ac508f6c76aa334d73a2f9ca0bf53317d078ddf43626ccfa10deb" ] ||
    fail "Tengine license checksum drifted"
  tongsuo_license=$(sha256sum /usr/share/licenses/trustdb-tlcp-gateway/Tongsuo-LICENSE.txt | cut -d " " -f1)
  [ "$tongsuo_license" = "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a" ] ||
    fail "Tongsuo license checksum drifted"
  tengine_version=$(/usr/local/sbin/tlcp-gateway -V 2>&1)
  case "$tengine_version" in
    *Tengine/2.3.4*) ;;
    *) fail "Tengine version drifted" ;;
  esac
  tongsuo_version=$(/opt/tongsuo/bin/openssl version 2>&1)
  case "$tongsuo_version" in
    *Tongsuo\ 8.4.0*) ;;
    *) fail "Tongsuo version drifted" ;;
  esac
'
if docker run --rm --platform "$platform" "$image_digest" >/dev/null 2>&1; then
  printf 'TLCP gateway unexpectedly started without a validated profile environment\n' >&2
  exit 1
fi

install -m 0644 "$work/gateway-first.oci.tar" "$output_dir/gateway-$platform_id.oci.tar"
install -m 0644 "$work/gateway.sbom.spdx.json" "$output_dir/gateway-$platform_id.sbom.spdx.json"
install -m 0644 "$work/gateway.build-record.json" "$output_dir/gateway-$platform_id.build-record.json"
install -m 0644 "$work/gateway.build-record.json.sha256" "$output_dir/gateway-$platform_id.build-record.json.sha256"

printf 'TLCP gateway image: %s\n' "$image_digest"
printf 'Verified artifacts: %s\n' "$output_dir"
