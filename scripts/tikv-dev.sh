#!/usr/bin/env bash
# Local TiKV+PD via Podman (native pod) or Compose for TrustDB integration tests.
# See also: scripts/tikv-dev.ps1 (Windows; default native Podman, no Docker CLI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${TRUSTDB_TIKV_COMPOSE_FILE:-docker-compose.tikv.yml}"
if [[ "${COMPOSE_FILE}" != /* ]]; then
  COMPOSE_FILE="${ROOT}/${COMPOSE_FILE}"
fi
PROJECT_NAME="trustdb-tikv-dev"

POD="trustdb-tikv-dev-pod"
VOL_PD="trustdb-tikv-dev-pd-vol"
VOL_TIKV="trustdb-tikv-dev-tikv-vol"
C_PD="trustdb-tikv-dev-pd"
C_TIKV="trustdb-tikv-dev-tikv"
IMG_PD="${TRUSTDB_TIKV_PD_IMAGE:-pingcap/pd:v7.5.0}"
IMG_TIKV="${TRUSTDB_TIKV_TIKV_IMAGE:-pingcap/tikv:v7.5.0}"

is_windowsish() {
  [[ -n "${WINDIR:-}" ]] || [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]
}

stack_mode() {
  local v
  v="$(echo "${TRUSTDB_TIKV_COMPOSE_VIA:-auto}" | tr '[:upper:]' '[:lower:]')"
  case "${v}" in
    native) printf '%s' native ;;
    podman) printf '%s' compose ;;
    docker-api) printf '%s' docker-api ;;
    auto)
      # Match tikv-dev.ps1: avoid flaky podman compose (e.g. SSH machine exit 125) on Windows shells.
      if is_windowsish && command -v podman >/dev/null 2>&1; then
        printf '%s' native
      elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
        printf '%s' compose
      else
        printf '%s' native
      fi
      ;;
    *)
      echo "Invalid TRUSTDB_TIKV_COMPOSE_VIA: ${TRUSTDB_TIKV_COMPOSE_VIA:-}" >&2
      exit 1
      ;;
  esac
}

require_stack_deps() {
  local m
  m="$(stack_mode)"
  case "${m}" in
    native)
      command -v podman >/dev/null 2>&1 || {
        echo "podman not found in PATH" >&2
        exit 1
      }
      ;;
    compose)
      command -v podman >/dev/null 2>&1 || {
        echo "podman not found in PATH" >&2
        exit 1
      }
      require_compose_file
      ;;
    docker-api)
      command -v docker >/dev/null 2>&1 || {
        echo "docker CLI not found in PATH" >&2
        exit 1
      }
      require_compose_file
      ;;
  esac
}

compose_podman() {
  echo "[tikv-dev] podman compose -f ${COMPOSE_FILE} -p ${PROJECT_NAME} $*"
  podman compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" "$@"
}

compose_docker_api() {
  local pipe="${TRUSTDB_TIKV_DOCKER_HOST:-npipe:////./pipe/docker_engine}"
  echo "[tikv-dev] docker compose -f ${COMPOSE_FILE} -p ${PROJECT_NAME} $* (DOCKER_HOST=${pipe})"
  DOCKER_HOST="${pipe}" docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" "$@"
}

ensure_volume() {
  if ! podman volume inspect "$1" >/dev/null 2>&1; then
    echo "[tikv-dev] podman volume create $1"
    podman volume create "$1"
  fi
}

pod_exists() {
  podman pod inspect "$POD" >/dev/null 2>&1
}

container_running() {
  [[ "$(podman container inspect "$1" --format '{{.State.Running}}' 2>/dev/null || true)" == "true" ]]
}

container_exists() {
  podman container inspect "$1" >/dev/null 2>&1
}

native_up() {
  command -v podman >/dev/null 2>&1 || {
    echo "podman not found in PATH" >&2
    exit 1
  }
  ensure_volume "$VOL_PD"
  ensure_volume "$VOL_TIKV"

  if pod_exists && container_running "$C_PD" && container_running "$C_TIKV"; then
    echo "[tikv-dev] native stack already running"
    return 0
  fi

  if pod_exists; then
    echo "[tikv-dev] podman pod start $POD"
    podman pod start "$POD" || true
    if ! container_exists "$C_PD"; then
      echo "[tikv-dev] error: pod without PD container; run: $0 reset" >&2
      exit 1
    fi
    if ! container_running "$C_PD"; then
      podman start "$C_PD" || true
    fi
    wait_pd
    if ! container_exists "$C_TIKV"; then
      echo "[tikv-dev] podman run TiKV ($IMG_TIKV)"
      podman run -d --pod "$POD" --name "$C_TIKV" -v "${VOL_TIKV}:/data/tikv" "$IMG_TIKV" \
        --addr=0.0.0.0:20160 --advertise-addr=127.0.0.1:20160 --status-addr=0.0.0.0:20180 \
        --pd=127.0.0.1:2379 --data-dir=/data/tikv
    elif ! container_running "$C_TIKV"; then
      podman start "$C_TIKV"
    fi
    return 0
  fi

  echo "[tikv-dev] podman pod create $POD (publish 2379,2380,20160,20180)"
  podman pod create --name "$POD" -p 2379:2379 -p 2380:2380 -p 20160:20160 -p 20180:20180
  echo "[tikv-dev] podman run PD ($IMG_PD)"
  podman run -d --pod "$POD" --name "$C_PD" -v "${VOL_PD}:/data" "$IMG_PD" \
    --name=pd --data-dir=/data/pd \
    --client-urls=http://0.0.0.0:2379 --peer-urls=http://0.0.0.0:2380 \
    --advertise-client-urls=http://127.0.0.1:2379 --advertise-peer-urls=http://127.0.0.1:2380 \
    --initial-cluster=pd=http://127.0.0.1:2380
  wait_pd
  echo "[tikv-dev] podman run TiKV ($IMG_TIKV)"
  podman run -d --pod "$POD" --name "$C_TIKV" -v "${VOL_TIKV}:/data/tikv" "$IMG_TIKV" \
    --addr=0.0.0.0:20160 --advertise-addr=127.0.0.1:20160 --status-addr=0.0.0.0:20180 \
    --pd=127.0.0.1:2379 --data-dir=/data/tikv
}

native_down() {
  podman pod rm -f "$POD" >/dev/null 2>&1 || true
}

native_reset() {
  native_down
  podman volume rm -f "$VOL_PD" "$VOL_TIKV" >/dev/null 2>&1 || true
}

native_logs() {
  if ! podman pod inspect "$POD" >/dev/null 2>&1; then
    echo "[tikv-dev] stack is not up (no pod). Run: $0 up" >&2
    exit 1
  fi
  echo "[tikv-dev] podman pod logs -f --tail 200 $POD"
  set +e
  podman pod logs -f --tail 200 "$POD"
  local st=$?
  set -e
  if [[ "$st" -ne 0 ]]; then
    echo "[tikv-dev] pod logs failed; following TiKV container" >&2
    podman logs -f --tail 200 "$C_TIKV"
  fi
}

native_ps() {
  echo "[tikv-dev] podman ps -a --filter pod=${POD}"
  podman ps -a --filter "pod=${POD}"
}

stack() {
  local m
  m="$(stack_mode)"
  case "${m}" in
    native)
      case "$1" in
        up)
          native_up
          ;;
        down)
          if [[ "${2:-}" == "-v" ]]; then
            native_reset
          else
            native_down
          fi
          ;;
        logs)
          native_logs
          ;;
        ps)
          native_ps
          ;;
        *)
          echo "native stack: bad command $*" >&2
          exit 1
          ;;
      esac
      ;;
    compose)
      compose_podman "$@"
      ;;
    docker-api)
      compose_docker_api "$@"
      ;;
  esac
}

require_compose_file() {
  if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "Compose file not found: ${COMPOSE_FILE}" >&2
    exit 1
  fi
}

wait_pd() {
  local deadline=$((SECONDS + 120))
  local url="http://127.0.0.1:2379/pd/api/v1/health"
  echo "[tikv-dev] waiting for PD ${url}"
  while ((SECONDS < deadline)); do
    if curl -fsS --max-time 3 "${url}" >/dev/null 2>&1; then
      echo "[tikv-dev] PD health OK"
      return 0
    fi
    sleep 2
  done
  echo "[tikv-dev] timed out waiting for PD" >&2
  return 1
}

wait_tikv() {
  local deadline=$((SECONDS + 180))
  local url="http://127.0.0.1:20180/status"
  echo "[tikv-dev] waiting for TiKV ${url}"
  while ((SECONDS < deadline)); do
    if curl -fsS --max-time 3 "${url}" >/dev/null 2>&1; then
      echo "[tikv-dev] TiKV status OK"
      return 0
    fi
    sleep 2
  done
  echo "[tikv-dev] timed out waiting for TiKV" >&2
  return 1
}

pd_endpoints() {
  if [[ -n "${TRUSTDB_TIKV_PD_ENDPOINTS:-}" ]]; then
    echo "${TRUSTDB_TIKV_PD_ENDPOINTS}"
  else
    echo "127.0.0.1:2379"
  fi
}

run_go_test() {
  export TRUSTDB_TIKV_PD_ENDPOINTS
  TRUSTDB_TIKV_PD_ENDPOINTS="$(pd_endpoints)"
  echo "[tikv-dev] TRUSTDB_TIKV_PD_ENDPOINTS=${TRUSTDB_TIKV_PD_ENDPOINTS}"
  if [[ -n "${TRUSTDB_TIKV_KEYSPACE:-}" ]]; then
    export TRUSTDB_TIKV_KEYSPACE
    echo "[tikv-dev] TRUSTDB_TIKV_KEYSPACE=${TRUSTDB_TIKV_KEYSPACE}"
  else
    unset TRUSTDB_TIKV_KEYSPACE || true
  fi
  echo "[tikv-dev] go test -count=1 -tags=integration ./internal/proofstore/tikv"
  go test -count=1 -tags=integration ./internal/proofstore/tikv
}

usage() {
  cat <<'EOF'
TrustDB local TiKV helper

Usage:
  ./scripts/tikv-dev.sh <command>

Commands:
  up           Start PD+TiKV and wait for health from host
  down         Stop stack (keep volumes)
  reset        Stop and delete volumes (clean cluster)
  test         Run: go test -count=1 -tags=integration ./internal/proofstore/tikv
  logs         Follow service logs
  ps           List containers for this dev pod / compose project

Env:
  TRUSTDB_TIKV_COMPOSE_FILE       Override compose file path (compose|docker-api only; native ignores)
  TRUSTDB_TIKV_PD_ENDPOINTS       Default 127.0.0.1:2379
  TRUSTDB_TIKV_KEYSPACE           Optional keyspace for tests
  TRUSTDB_TIKV_PD_IMAGE           PD image (native + compose interpolation; default pingcap/pd:v7.5.0)
  TRUSTDB_TIKV_TIKV_IMAGE         TiKV image (native + compose; default pingcap/tikv:v7.5.0)
  TRUSTDB_TIKV_COMPOSE_VIA        auto | native | podman | docker-api (default auto)
  TRUSTDB_TIKV_DOCKER_HOST        docker-api on Windows: npipe (default npipe:////./pipe/docker_engine)

  See scripts/tikv-dev.env.example for a copy-paste .env template (compose reads repo-root .env).
EOF
}

cmd="${1:-help}"

case "${cmd}" in
  up|down|reset|logs|ps)
    require_stack_deps
    ;;
esac

case "${cmd}" in
  up)
    stack up -d
    wait_pd
    wait_tikv
    echo "[tikv-dev] stack is up. Run: ./scripts/tikv-dev.sh test"
    ;;
  down)
    stack down
    ;;
  reset)
    stack down -v
    echo "[tikv-dev] volumes removed"
    ;;
  test)
    run_go_test
    ;;
  logs)
    stack logs -f --tail 200
    ;;
  ps)
    stack ps
    ;;
  help | -h | --help | "")
    usage
    ;;
  *)
    echo "Unknown command: ${cmd}" >&2
    usage
    exit 1
    ;;
esac
