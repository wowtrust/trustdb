#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)
BASELINE="${REPO_ROOT}/configs/compatibility/fisco-bcos-v3.16.3.json"
COMPAT="${SCRIPT_DIR}/compatibility.py"
WAIT_AIR_READY="${SCRIPT_DIR}/wait_air_ready.py"
MODE=""
WORK_DIR=""
CACHE_DIR_ARG=""
P2P_PORT=${BCOS_P2P_PORT:-31300}
RPC_PORT=${BCOS_RPC_PORT:-21200}
ADMIN_ADDRESS=0x0000000000000000000000000000000000000001
RAW_EVM_FIXTURE=false
QUALIFICATION=false
PERFORMANCE_WARMUP=5
PERFORMANCE_SAMPLES=20
ROOT_SM_CERT_WAS_PRESENT=false
ROOT_SM_PARAM_WAS_PRESENT=false
[[ -e ${REPO_ROOT}/sm_cert.cnf ]] && ROOT_SM_CERT_WAS_PRESENT=true
[[ -e ${REPO_ROOT}/sm_sm2.param ]] && ROOT_SM_PARAM_WAS_PRESENT=true

usage() {
    echo "usage: $0 --mode standard|guomi --work-dir DIR [--cache-dir DIR] [--qualification] [--raw-evm-fixture] [--p2p-port PORT] [--rpc-port PORT] [--performance-warmup 3-20] [--performance-samples 20-100]" >&2
}

while (($#)); do
    case "$1" in
        --mode) MODE=$2; shift 2 ;;
        --work-dir) WORK_DIR=$2; shift 2 ;;
        --cache-dir) CACHE_DIR_ARG=$2; shift 2 ;;
        --p2p-port) P2P_PORT=$2; shift 2 ;;
        --rpc-port) RPC_PORT=$2; shift 2 ;;
        --performance-warmup) PERFORMANCE_WARMUP=$2; shift 2 ;;
        --performance-samples) PERFORMANCE_SAMPLES=$2; shift 2 ;;
        --qualification) QUALIFICATION=true; shift ;;
        --raw-evm-fixture) RAW_EVM_FIXTURE=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ ${MODE} != standard && ${MODE} != guomi ]]; then
    usage
    exit 2
fi
if [[ -z ${WORK_DIR} ]]; then
    echo "--work-dir is required so evidence is not written to an ambiguous temporary path" >&2
    exit 2
fi
if [[ ${QUALIFICATION} == true && ${RAW_EVM_FIXTURE} == true ]]; then
    echo "--qualification requires the production TrustDB anchor contract" >&2
    exit 2
fi
if [[ ! ${PERFORMANCE_WARMUP} =~ ^[0-9]+$ ]] || \
   ((PERFORMANCE_WARMUP < 3 || PERFORMANCE_WARMUP > 20)); then
    echo "--performance-warmup must be an integer between 3 and 20" >&2
    exit 2
fi
if [[ ! ${PERFORMANCE_SAMPLES} =~ ^[0-9]+$ ]] || \
   ((PERFORMANCE_SAMPLES < 20 || PERFORMANCE_SAMPLES > 100)); then
    echo "--performance-samples must be an integer between 20 and 100" >&2
    exit 2
fi

for port_name in P2P_PORT RPC_PORT; do
    port_value=${!port_name}
    if [[ ! ${port_value} =~ ^[0-9]+$ ]] || ((port_value < 1 || port_value > 65532)); then
        echo "${port_name} must be a numeric base port between 1 and 65532" >&2
        exit 2
    fi
done
if ((P2P_PORT <= RPC_PORT + 3 && RPC_PORT <= P2P_PORT + 3)); then
    echo "the four-port P2P and RPC ranges must not overlap" >&2
    exit 2
fi
if [[ -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
    read -r EPHEMERAL_START EPHEMERAL_END </proc/sys/net/ipv4/ip_local_port_range
    for port_name in P2P_PORT RPC_PORT; do
        port_value=${!port_name}
        if ((port_value <= EPHEMERAL_END && port_value + 3 >= EPHEMERAL_START)); then
            echo "${port_name} range ${port_value}-$((port_value + 3)) overlaps the Linux ephemeral range ${EPHEMERAL_START}-${EPHEMERAL_END}" >&2
            exit 2
        fi
    done
fi
if [[ -e ${WORK_DIR} ]]; then
    echo "work directory already exists: ${WORK_DIR}" >&2
    exit 1
fi

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) PLATFORM=linux/amd64 ;;
    Linux/aarch64|Linux/arm64) PLATFORM=linux/arm64 ;;
    Darwin/x86_64) PLATFORM=darwin/amd64 ;;
    Darwin/arm64) PLATFORM=darwin/arm64 ;;
    *) echo "unsupported smoke host: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

python3 "${COMPAT}" check \
    --deployment air --crypto "${MODE}" --platform "${PLATFORM}" --level artifact >/dev/null

mkdir -p "${WORK_DIR}" "${WORK_DIR}/home/.fisco" "${WORK_DIR}/unpack"
WORK_DIR=$(cd -- "${WORK_DIR}" && pwd)
if [[ -n ${CACHE_DIR_ARG} ]]; then
    mkdir -p "${CACHE_DIR_ARG}"
    CACHE_DIR=$(cd -- "${CACHE_DIR_ARG}" && pwd)
else
    mkdir -p "${WORK_DIR}/cache"
    CACHE_DIR="${WORK_DIR}/cache"
fi
HOST_GOMODCACHE=${GOMODCACHE:-$(go env GOMODCACHE)}
HOST_GOCACHE=${GOCACHE:-$(go env GOCACHE)}
export HOME="${WORK_DIR}/home"
export GOMODCACHE="${HOST_GOMODCACHE}"
export GOCACHE="${HOST_GOCACHE}"

python3 "${COMPAT}" verify-artifacts \
    --platform "${PLATFORM}" --crypto "${MODE}" --cache-dir "${CACHE_DIR}" \
    >"${WORK_DIR}/artifact-verification.json"

artifact_name() {
    local component=$1
    python3 - "${BASELINE}" "${component}" "${PLATFORM}" "${MODE}" <<'PY'
import json
import sys

baseline, component, platform, crypto = sys.argv[1:]
with open(baseline, encoding="utf-8") as handle:
    value = json.load(handle)
for artifact in value["components"][component]["artifacts"]:
    if artifact["platform"] != platform:
        continue
    if component == "solidity" and artifact["crypto"] != crypto:
        continue
    print(artifact["name"])
    break
else:
    raise SystemExit(f"no {component} artifact for {platform}/{crypto}")
PY
}

NODE_ARCHIVE="${CACHE_DIR}/node/$(artifact_name node)"
CSDK_ARCHIVE="${CACHE_DIR}/c_sdk/$(artifact_name c_sdk)"
SOLC_ARCHIVE="${CACHE_DIR}/solidity/$(artifact_name solidity)"
TASSL_ARCHIVE="${CACHE_DIR}/tassl/$(artifact_name tassl)"

mkdir -p "${WORK_DIR}/unpack/node" "${WORK_DIR}/unpack/solc" "${WORK_DIR}/unpack/tassl"
tar -xzf "${NODE_ARCHIVE}" -C "${WORK_DIR}/unpack/node"
tar -xzf "${SOLC_ARCHIVE}" -C "${WORK_DIR}/unpack/solc"
tar -xzf "${TASSL_ARCHIVE}" -C "${WORK_DIR}/unpack/tassl"

NODE_BIN=$(find "${WORK_DIR}/unpack/node" -type f -name fisco-bcos -print -quit)
SOLC_BIN=$(find "${WORK_DIR}/unpack/solc" -type f \( -name solc -o -name 'solc-0.8.11*' \) -print -quit)
TASSL_BIN=$(find "${WORK_DIR}/unpack/tassl" -type f -name 'tassl-1.1.1b*' -print -quit)
if [[ -z ${NODE_BIN} || -z ${SOLC_BIN} || -z ${TASSL_BIN} ]]; then
    echo "one or more pinned archives did not contain the expected executable" >&2
    exit 1
fi
chmod +x "${NODE_BIN}" "${SOLC_BIN}" "${TASSL_BIN}"
if [[ ${PLATFORM} == darwin/* ]]; then
    # Codex/GUI-originated downloads can inherit Gatekeeper quarantine metadata.
    # The archive bytes were verified above; clear only the extracted executables.
    xattr -d com.apple.quarantine "${NODE_BIN}" "${SOLC_BIN}" "${TASSL_BIN}" 2>/dev/null || true
fi
cp "${TASSL_BIN}" "${HOME}/.fisco/tassl-1.1.1b"

BUILD_CHAIN="${WORK_DIR}/build_chain.sh"
python3 - "${BASELINE}" "${BUILD_CHAIN}" <<'PY'
import hashlib
import json
import sys
import urllib.request

baseline, destination = sys.argv[1:]
with open(baseline, encoding="utf-8") as handle:
    pin = json.load(handle)["components"]["node"]["build_chain"]
request = urllib.request.Request(pin["url"], headers={"User-Agent": "trustdb-fisco-compat/1"})
data = urllib.request.urlopen(request).read()
actual = hashlib.sha256(data).hexdigest()
if actual != pin["sha256"]:
    raise SystemExit(f"build_chain sha256 mismatch: expected {pin['sha256']}, got {actual}")
with open(destination, "wb") as output:
    output.write(data)
PY
chmod +x "${BUILD_CHAIN}"

"${NODE_BIN}" --version >"${WORK_DIR}/node-version.txt"
if "${SOLC_BIN}" --version >"${WORK_DIR}/solc-version.txt" 2>&1; then
    SOLC_EXECUTABLE=true
else
    SOLC_EXECUTABLE=false
    if [[ ${RAW_EVM_FIXTURE} != true ]]; then
        echo "the pinned Solidity compiler could not execute; see ${WORK_DIR}/solc-version.txt" >&2
        sed 's/^/  /' "${WORK_DIR}/solc-version.txt" >&2
        exit 1
    fi
fi
"${TASSL_BIN}" version >"${WORK_DIR}/tassl-version.txt"

if [[ ${RAW_EVM_FIXTURE} != true ]]; then
    mkdir -p "${WORK_DIR}/contract"
    if ! "${SOLC_BIN}" --bin --abi --overwrite \
        -o "${WORK_DIR}/contract" "${SCRIPT_DIR}/CompatibilityProbe.sol" \
        >"${WORK_DIR}/compiler-build.log" 2>&1; then
        echo "the pinned Solidity compiler failed to build CompatibilityProbe.sol" >&2
        sed 's/^/  /' "${WORK_DIR}/compiler-build.log" >&2
        exit 1
    fi
fi

NODE_DIR="${WORK_DIR}/nodes-${MODE}"
BUILD_ARGS=(
    -l 127.0.0.1:4
    -p "${P2P_PORT},${RPC_PORT}"
    -o "${NODE_DIR}"
    -e "${NODE_BIN}"
    -v v3.16.3
)
if [[ ${QUALIFICATION} != true ]]; then
    BUILD_ARGS+=(-a "${ADMIN_ADDRESS}")
fi
if [[ ${MODE} == guomi ]]; then
    BUILD_ARGS+=(-s)
fi
(
    cd "${WORK_DIR}"
    bash "${BUILD_CHAIN}" "${BUILD_ARGS[@]}"
) >"${WORK_DIR}/build-chain.log" 2>&1

NODE_PARENT="${NODE_DIR}/127.0.0.1"
SDK_DIR="${NODE_PARENT}/sdk"
if [[ ${MODE} == guomi ]]; then
    (
        cd "${WORK_DIR}"
        "${TASSL_BIN}" verify -CAfile "${SDK_DIR}/sm_ca.crt" "${SDK_DIR}/sm_sdk.crt" \
            >"${WORK_DIR}/certificate-verification.txt"
        "${TASSL_BIN}" verify -CAfile "${SDK_DIR}/sm_ca.crt" "${SDK_DIR}/sm_ensdk.crt" \
            >>"${WORK_DIR}/certificate-verification.txt"
    )
else
    "${TASSL_BIN}" verify -CAfile "${SDK_DIR}/ca.crt" "${SDK_DIR}/sdk.crt" \
        >"${WORK_DIR}/certificate-verification.txt"
fi

export CGO_ENABLED=1
CSDK_DIR=$(dirname "${CSDK_ARCHIVE}")
export CGO_LDFLAGS="-L${CSDK_DIR}"
if [[ ${PLATFORM} == darwin/* ]]; then
    # The upstream dylib install name uses @rpath. Embed the verified cache
    # directory so CI and developer shells do not depend on DYLD_* inheritance.
    export CGO_LDFLAGS="${CGO_LDFLAGS} -Wl,-rpath,${CSDK_DIR}"
    export DYLD_LIBRARY_PATH="${CSDK_DIR}${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"
else
    export LD_LIBRARY_PATH="${CSDK_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
fi

if ! (
    cd "${SCRIPT_DIR}/smoke-client"
    GOWORK=off go build -mod=readonly -trimpath -o "${WORK_DIR}/smoke-client" .
) >"${WORK_DIR}/smoke-client-build.log" 2>&1; then
    echo "the Go SDK smoke client failed to build" >&2
    sed 's/^/  /' "${WORK_DIR}/smoke-client-build.log" >&2
    exit 1
fi

if [[ ${QUALIFICATION} == true ]]; then
    if ! (
        cd "${REPO_ROOT}"
        go test -c -mod=readonly -trimpath -tags=fiscobcos_sdk \
            -o "${WORK_DIR}/bcos-qualification.test" ./internal/sproof
        go build -mod=readonly -trimpath \
            -o "${WORK_DIR}/offline-qualification" \
            ./scripts/fisco-bcos/offline-qualification
    ) >"${WORK_DIR}/qualification-build.log" 2>&1; then
        echo "the TrustDB BCOS qualification binaries failed to build" >&2
        sed 's/^/  /' "${WORK_DIR}/qualification-build.log" >&2
        exit 1
    fi
fi

NODE_PIDS=()

start_node() {
    local index=$1
    local node_dir="${NODE_PARENT}/node${index}"
    local pid
    local ready=false
    local attempt

    : >"${node_dir}/nohup.out"
    (
        cd "${node_dir}"
        nohup ../fisco-bcos -c config.ini -g config.genesis >>nohup.out 2>&1 &
        printf '%s\n' "$!" >.trustdb-smoke.pid
    )
    pid=$(<"${node_dir}/.trustdb-smoke.pid")
    NODE_PIDS[index]="${pid}"

    for attempt in {1..40}; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "node${index} exited during startup" >&2
            tail -80 "${node_dir}/nohup.out" >&2
            return 1
        fi
        if grep -q "fisco-bcos is running" "${node_dir}/nohup.out"; then
            ready=true
            break
        fi
        sleep 0.5
    done
    if [[ ${ready} != true ]]; then
        echo "node${index} did not become ready within 20 seconds" >&2
        tail -80 "${node_dir}/nohup.out" >&2
        return 1
    fi
    printf 'node%s pid=%s ready\n' "${index}" "${pid}" >>"${WORK_DIR}/node-start.log"
}

stop_node() {
    local index=$1
    local pid=${NODE_PIDS[index]:-}
    local attempt

    [[ -z ${pid} ]] && return 0
    kill -TERM "${pid}" 2>/dev/null || true
    for attempt in {1..60}; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            NODE_PIDS[index]=""
            printf 'node%s pid=%s stopped\n' "${index}" "${pid}" >>"${WORK_DIR}/node-stop.log"
            return 0
        fi
        sleep 0.5
    done
    kill -KILL "${pid}" 2>/dev/null || true
    NODE_PIDS[index]=""
    echo "node${index} required SIGKILL" >&2
    return 1
}

stop_nodes() {
    local pid
    local attempt
    local running

    # Bash 3.2 treats "${empty_array[@]}" as an unbound variable under
    # `set -u`. The normal path clears this array before the EXIT trap runs.
    if ((${#NODE_PIDS[@]} == 0)); then
        return 0
    fi

    for ((index=${#NODE_PIDS[@]} - 1; index >= 0; index--)); do
        pid=${NODE_PIDS[index]:-}
        [[ -z ${pid} ]] && continue
        kill -TERM "${pid}" 2>/dev/null || true
    done

    for attempt in {1..60}; do
        running=false
        for pid in "${NODE_PIDS[@]}"; do
            [[ -z ${pid} ]] && continue
            if kill -0 "${pid}" 2>/dev/null; then
                running=true
                break
            fi
        done
        [[ ${running} == false ]] && return 0
        sleep 0.5
    done

    for pid in "${NODE_PIDS[@]}"; do
        [[ -z ${pid} ]] && continue
        kill -KILL "${pid}" 2>/dev/null || true
    done
    return 1
}

cleanup() {
    stop_nodes >/dev/null 2>&1 || true
    if [[ ${QUALIFICATION} == true && -n ${ACCOUNT_KEY_FILE:-} ]]; then
        rm -f "${ACCOUNT_KEY_FILE}"
    fi
    if [[ -n ${SMOKE_LOCK:-} ]]; then
        rm -f "${SMOKE_LOCK}/pid"
        rmdir "${SMOKE_LOCK}" 2>/dev/null || true
    fi
    # An EXIT trap must not turn an otherwise successful smoke run into a
    # failure when the normal path has already released and cleared the lock.
    return 0
}
SMOKE_LOCK="${TMPDIR:-/tmp}/trustdb-fisco-bcos-smoke-${PLATFORM//\//-}.lock"
if ! mkdir "${SMOKE_LOCK}" 2>/dev/null; then
    echo "another FISCO BCOS smoke owns ${SMOKE_LOCK}; standard and Guomi runs must be sequential" >&2
    exit 1
fi
printf '%s\n' "$$" >"${SMOKE_LOCK}/pid"
trap cleanup EXIT INT TERM

if [[ ${QUALIFICATION} == true ]]; then
    ACCOUNT_KEY_FILE="${WORK_DIR}/publisher.key"
    python3 - "${ACCOUNT_KEY_FILE}" <<'PY'
import secrets
import sys
from pathlib import Path

# The smaller bound makes the scalar valid for both secp256k1 and SM2.
upper = min(
    int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
    int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16),
)
value = secrets.randbelow(upper - 1) + 1
destination = Path(sys.argv[1])
destination.write_text(f"{value:064x}\n", encoding="ascii")
destination.chmod(0o600)
PY
fi

# The generated start scripts identify a process only by the shared node
# executable path. They therefore cannot safely start these four nodes in
# sequence, while starting all four at once has exposed an upstream gateway
# race on high-core Linux hosts. Own the exact PID of every node instead.
for index in 0 1 2 3; do
    start_node "${index}"
    sleep 2
done

for index in 0 1 2 3; do
    if ! kill -0 "${NODE_PIDS[index]}" 2>/dev/null; then
        echo "node${index} is not running" >&2
        exit 1
    fi
done

# A live RPC listener is insufficient: the native SDK waits for usable group
# membership after the websocket handshake. Avoid entering that opaque timeout
# path until every node has observed all four members.
AIR_READY_TIMEOUT=30
[[ ${QUALIFICATION} == true ]] && AIR_READY_TIMEOUT=60
python3 "${WAIT_AIR_READY}" \
    --node-parent "${NODE_PARENT}" --node-count 4 --timeout-seconds "${AIR_READY_TIMEOUT}"

for index in 0 1 2 3; do
    if ! kill -0 "${NODE_PIDS[index]}" 2>/dev/null; then
        echo "node${index} exited during the four-node convergence check" >&2
        exit 1
    fi
done

CLIENT_ARGS=(
    --mode "${MODE}"
    --host 127.0.0.1
    --port "${RPC_PORT}"
    --cert-dir "${SDK_DIR}"
    --performance-warmup "${PERFORMANCE_WARMUP}"
    --performance-samples "${PERFORMANCE_SAMPLES}"
)
if [[ ${RAW_EVM_FIXTURE} == true ]]; then
    CLIENT_ARGS+=(--raw-evm-fixture)
elif [[ ${QUALIFICATION} == true ]]; then
    CLIENT_ARGS+=(
        --abi "${REPO_ROOT}/contracts/fisco-bcos/artifacts/${MODE}/TrustDBAnchorV1.abi"
        --bin "${REPO_ROOT}/contracts/fisco-bcos/artifacts/${MODE}/TrustDBAnchorV1.bin"
        --anchor-v1-constructor
        --account-key-file "${ACCOUNT_KEY_FILE}"
    )
else
    CLIENT_ARGS+=(
        --abi "${WORK_DIR}/contract/CompatibilityProbe.abi"
        --bin "${WORK_DIR}/contract/CompatibilityProbe.bin"
    )
fi
if [[ ${QUALIFICATION} == true ]]; then
    SCENARIO_DIR="${WORK_DIR}/qualification-scenarios"
    mkdir -p "${SCENARIO_DIR}"
    CLIENT_ARGS+=(
        --scenario-dir "${SCENARIO_DIR}"
        --restart-port "$((RPC_PORT + 3))"
    )
fi

wait_for_scenario_marker() {
    local marker=$1
    local attempt

    for attempt in {1..1200}; do
        if [[ -e ${marker} ]]; then
            return 0
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            echo "the Go SDK smoke client exited before scenario marker ${marker}" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "timed out waiting for scenario marker ${marker}" >&2
    return 1
}

four_member_observation_count() {
    local node_dir=$1
    local count
    count=$(
        grep -h "notifyGroupNodeInfo,connectedNodeSize=4" \
            "${node_dir}"/log/log_*.log 2>/dev/null | wc -l | tr -d ' '
    )
    printf '%s\n' "${count:-0}"
}

(
    cd "${WORK_DIR}"
    exec "${WORK_DIR}/smoke-client" "${CLIENT_ARGS[@]}"
) >"${WORK_DIR}/client-evidence.json" \
  2>"${WORK_DIR}/client-stderr.log" &
CLIENT_PID=$!

if [[ ${QUALIFICATION} == true ]]; then
    wait_for_scenario_marker "${SCENARIO_DIR}/node-loss.ready"
    stop_node 3
    for index in 0 1 2; do
        if ! kill -0 "${NODE_PIDS[index]}" 2>/dev/null; then
            echo "node${index} exited while removing node3" >&2
            exit 1
        fi
    done
    printf 'node3_offline=true\n' >"${WORK_DIR}/node-loss-stage.txt"
    : >"${SCENARIO_DIR}/node-loss.continue"

    wait_for_scenario_marker "${SCENARIO_DIR}/node-restart.ready"
    mv "${NODE_PARENT}/node3/log" "${NODE_PARENT}/node3/log-before-restart"
    mkdir "${NODE_PARENT}/node3/log"
    start_node 3
    NODE3_RECONVERGED=false
    for attempt in {1..120}; do
        NODE3_FOUR_MEMBER_AFTER=$(four_member_observation_count "${NODE_PARENT}/node3")
        if ((NODE3_FOUR_MEMBER_AFTER > 0)); then
            NODE3_RECONVERGED=true
            break
        fi
        if ! kill -0 "${NODE_PIDS[3]}" 2>/dev/null; then
            echo "node3 exited while rejoining the four-node group" >&2
            exit 1
        fi
        sleep 0.5
    done
    if [[ ${NODE3_RECONVERGED} != true ]]; then
        echo "node3 did not observe a fresh four-member group after restart" >&2
        exit 1
    fi
    : >"${SCENARIO_DIR}/node-restart.continue"
fi

if ! wait "${CLIENT_PID}"; then
    echo "the Go SDK smoke client failed" >&2
    sed 's/^/  /' "${WORK_DIR}/client-stderr.log" >&2
    exit 1
fi

if [[ ${QUALIFICATION} == true ]]; then
    QUALIFICATION_OUTPUT="${WORK_DIR}/qualification"
    mkdir -p "${QUALIFICATION_OUTPUT}"
    if ! (
        cd "${REPO_ROOT}"
        TRUSTDB_BCOS_QUALIFICATION=1 \
        TRUSTDB_BCOS_CLIENT_EVIDENCE="${WORK_DIR}/client-evidence.json" \
        TRUSTDB_BCOS_CERT_DIR="${SDK_DIR}" \
        TRUSTDB_BCOS_ACCOUNT_KEY="${ACCOUNT_KEY_FILE}" \
        TRUSTDB_BCOS_OUTPUT_DIR="${QUALIFICATION_OUTPUT}" \
        TRUSTDB_BCOS_RPC_PORT="${RPC_PORT}" \
        TRUSTDB_REPO_ROOT="${REPO_ROOT}" \
            "${WORK_DIR}/bcos-qualification.test" \
            -test.run '^TestLiveBCOSFourNodeQualification$' \
            -test.count=1 -test.v
    ) >"${WORK_DIR}/qualification-test.log" 2>&1; then
        echo "the live TrustDB BCOS qualification failed" >&2
        sed 's/^/  /' "${WORK_DIR}/qualification-test.log" >&2
        exit 1
    fi
fi

if ! stop_nodes; then
    echo "one or more FISCO BCOS nodes required SIGKILL during teardown" >&2
    exit 1
fi
NODE_PIDS=()

if [[ ${QUALIFICATION} == true ]]; then
    rm -f "${ACCOUNT_KEY_FILE}"
fi

python3 - "${P2P_PORT}" "${RPC_PORT}" <<'PY'
import socket
import sys

for base in (int(sys.argv[1]), int(sys.argv[2])):
    for port in range(base, base + 4):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(f"FISCO BCOS listener still accepts connections on port {port}")
PY

if [[ ${QUALIFICATION} == true ]]; then
    if [[ $(uname -s) != Linux ]]; then
        echo "--qualification offline verification requires a Linux network namespace" >&2
        exit 1
    fi
    if ! command -v unshare >/dev/null 2>&1; then
        echo "--qualification requires the util-linux unshare command" >&2
        exit 1
    fi
    OFFLINE_REPORT="${WORK_DIR}/qualification/offline-verification.json"
    OFFLINE_COMMAND=(
        "${WORK_DIR}/offline-qualification"
        --proof "${WORK_DIR}/qualification/portable.sproof"
        --content "${WORK_DIR}/qualification/content.bin"
        --trust-roots "${WORK_DIR}/qualification/trust-roots.json"
        --output "${OFFLINE_REPORT}"
    )
    if [[ $(id -u) -eq 0 ]]; then
        OFFLINE_RUNNER=(env TRUSTDB_NETWORK_DISABLED=1 unshare --net --)
    else
        OFFLINE_RUNNER=(sudo env TRUSTDB_NETWORK_DISABLED=1 unshare --net --)
    fi
    if ! "${OFFLINE_RUNNER[@]}" "${OFFLINE_COMMAND[@]}" \
        >"${WORK_DIR}/offline-qualification.log" 2>&1; then
        echo "the disconnected TrustDB BCOS verification failed" >&2
        sed 's/^/  /' "${WORK_DIR}/offline-qualification.log" >&2
        exit 1
    fi
    if [[ $(id -u) -ne 0 ]]; then
        sudo chown "$(id -u):$(id -g)" "${OFFLINE_REPORT}"
    fi
fi

if ! (
    cd "${REPO_ROOT}"
    GOWORK=off go run -mod=readonly ./scripts/fisco-bcos/evidence-check \
        --input "${WORK_DIR}/client-evidence.json" \
        --cert-dir "${SDK_DIR}"
) >"${WORK_DIR}/consensus-preimage.json" \
  2>"${WORK_DIR}/consensus-preimage.stderr"; then
    echo "the production consensus-preimage evidence check failed" >&2
    sed 's/^/  /' "${WORK_DIR}/consensus-preimage.stderr" >&2
    exit 1
fi

if ! python3 "${SCRIPT_DIR}/performance.py" \
    --client "${WORK_DIR}/client-evidence.json" \
    --verification "${WORK_DIR}/consensus-preimage.json" \
    >"${WORK_DIR}/performance.json" 2>"${WORK_DIR}/performance.stderr"; then
    echo "the post-warmup performance evidence aggregation failed" >&2
    sed 's/^/  /' "${WORK_DIR}/performance.stderr" >&2
    exit 1
fi

rm -f "${SMOKE_LOCK}/pid"
rmdir "${SMOKE_LOCK}"
SMOKE_LOCK=""

if [[ ${ROOT_SM_CERT_WAS_PRESENT} == false && -e ${REPO_ROOT}/sm_cert.cnf ]] || \
   [[ ${ROOT_SM_PARAM_WAS_PRESENT} == false && -e ${REPO_ROOT}/sm_sm2.param ]]; then
    echo "smoke subprocess polluted the repository root with TASSL helper files" >&2
    exit 1
fi

python3 - "${WORK_DIR}" "${BASELINE}" "${MODE}" "${PLATFORM}" "${SOLC_EXECUTABLE}" \
    "${CACHE_DIR}" "${P2P_PORT}" "${RPC_PORT}" "${RAW_EVM_FIXTURE}" \
    "${PERFORMANCE_WARMUP}" "${PERFORMANCE_SAMPLES}" "${QUALIFICATION}" <<'PY'
import datetime
import json
import platform
import re
import shlex
import sys
from pathlib import Path

work = Path(sys.argv[1])
(
    baseline_path,
    mode,
    target_platform,
    compiler_executable,
    cache_dir,
    p2p_port,
    rpc_port,
    raw_evm_fixture,
    performance_warmup,
    performance_samples,
    qualification,
) = sys.argv[2:]
client = json.loads((work / "client-evidence.json").read_text(encoding="utf-8"))
preimages = json.loads((work / "consensus-preimage.json").read_text(encoding="utf-8"))
performance = json.loads((work / "performance.json").read_text(encoding="utf-8"))
if preimages.get("receipt_consensus_hash_matched") is not True:
    raise SystemExit("production receipt consensus preimage did not match the node hash")
if preimages.get("block_consensus_hash_matched") is not True:
    raise SystemExit("production block consensus preimage did not match the node hash")
if preimages.get("pbft_commit_signatures_valid") is not True:
    raise SystemExit("production PBFT commit signatures did not verify")
raw_fixture = raw_evm_fixture == "true"
if not raw_fixture and client.get("production_publish_verified") is not True:
    raise SystemExit("production publish event and getAnchor record were not verified")
if not raw_fixture and not client.get("anchor_payload"):
    raise SystemExit("production publish payload evidence is missing")
qualified = qualification == "true"
if qualified and not client.get("qualification"):
    raise SystemExit("four-node qualification evidence is missing")
live_qualification = None
offline_qualification = None
if qualified:
    live_qualification = json.loads(
        (work / "qualification" / "live-qualification.json").read_text(encoding="utf-8")
    )
    offline_qualification = json.loads(
        (work / "qualification" / "offline-verification.json").read_text(encoding="utf-8")
    )
    if offline_qualification.get("network_disabled_by_gate") is not True:
        raise SystemExit("offline qualification did not record a disabled network namespace")
    if offline_qualification.get("external_network_access") is not False:
        raise SystemExit("offline qualification reported external network access")
    if offline_qualification.get("external_provider_access") is not False:
        raise SystemExit("offline qualification reported external provider access")
    cases = {case.get("name"): case for case in offline_qualification.get("cases", [])}
    if cases.get("complete_l5", {}).get("valid") is not True:
        raise SystemExit("offline qualification did not produce a valid complete L5 case")
    for name in ("content_tamper", "receipt_inclusion_tamper", "pbft_finality_tamper", "exact_binding_tamper"):
        if cases.get(name, {}).get("valid") is not False:
            raise SystemExit(f"offline qualification did not reject {name}")
artifacts = json.loads((work / "artifact-verification.json").read_text(encoding="utf-8"))
baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
environment = {
    "platform": target_platform,
    "host_platform": platform.platform(),
    "python": platform.python_version(),
    "node_version": (work / "node-version.txt").read_text(encoding="utf-8"),
    "solc_version": (work / "solc-version.txt").read_text(encoding="utf-8"),
    "tassl_version": (work / "tassl-version.txt").read_text(encoding="utf-8"),
    "compiler_executable": compiler_executable == "true",
}

node_version_text = environment["node_version"]
version_match = re.search(r"FISCO BCOS Version\s*:\s*([^\s]+)", node_version_text)
commit_match = re.search(r"Git Commit\s*:\s*([0-9a-f]{40})", node_version_text)
if version_match is None or commit_match is None:
    raise SystemExit("could not parse the pinned node version and commit")

artifact_entries = artifacts["artifacts"]
if isinstance(artifact_entries, list):
    artifact_digests = {entry["name"]: entry["sha256"] for entry in artifact_entries}
elif isinstance(artifact_entries, dict):
    artifact_digests = artifact_entries
else:
    raise SystemExit("artifact verification has an unsupported result shape")

consensus = client["consensus_status"]
if isinstance(consensus, str):
    consensus = json.loads(consensus)
connected_nodes = consensus["connectedNodeList"]
if isinstance(connected_nodes, list):
    connected_nodes = len(connected_nodes)

def with_prefix(value: str) -> str:
    return value if value.startswith("0x") else "0x" + value

def transaction(value: dict, *, event_match: bool = False) -> dict:
    result = {
        "transaction_hash": with_prefix(value["hash"]),
        "status": value["status"],
        "block_number": value["block_number"],
        "transaction_proof": value["transaction_proof"],
        "receipt_proof": value["receipt_proof"],
    }
    if value.get("contract_address"):
        result["contract_address"] = value["contract_address"]
    if event_match:
        result["event_transaction_match"] = (
            with_prefix(client["event"]["transactionHash"]).lower()
            == result["transaction_hash"].lower()
        )
    return result

components = baseline["components"]
pins = {
    "node": f"{components['node']['tag']}@{components['node']['commit']}",
    "go_sdk": f"{components['go_sdk']['tag']}@{components['go_sdk']['commit']}",
    "c_sdk_source": components["go_sdk"]["c_sdk_module"]["commit"],
    "c_sdk_native": f"{components['c_sdk']['tag']}@{components['c_sdk']['commit']}",
    "solidity": f"{components['solidity']['tag']}@{components['solidity']['commit']}",
    "tassl": f"{components['tassl']['tag']}@{components['tassl']['commit']}",
}
command = [
    "scripts/fisco-bcos/smoke-air.sh",
    "--mode", mode,
    "--work-dir", str(work),
    "--cache-dir", cache_dir,
    "--p2p-port", p2p_port,
    "--rpc-port", rpc_port,
    "--performance-warmup", performance_warmup,
    "--performance-samples", performance_samples,
]
if raw_fixture:
    command.append("--raw-evm-fixture")
if qualified:
    command.append("--qualification")

block = client["containing_block"]
client_stderr = (work / "client-stderr.log").read_text(encoding="utf-8").splitlines()
evidence = {
    "schema_version": 1,
    "evidence_class": "diagnostic_partial" if raw_fixture else "runtime_verified",
    "admitted": not raw_fixture,
    "baseline_id": baseline["baseline_id"],
    "date": datetime.date.today().isoformat(),
    "profile": {
        "deployment": "air",
        "crypto": mode,
        "platform": target_platform,
    },
    "command": shlex.join(command),
    "host": environment["host_platform"],
    "pins": pins,
    "artifacts": artifact_digests,
    "node_version": version_match.group(1),
    "node_commit": commit_match.group(1),
    "certificate_verification": (work / "certificate-verification.txt").read_text(encoding="utf-8").splitlines(),
    "sm_crypto": client["sm_crypto"],
    "probe_source": client["probe_source"],
    "compiler_executable": environment["compiler_executable"],
    "clean_teardown": client["clean_teardown"],
    "node_clean_teardown": True,
    "environment": environment,
    "harness_validation": {
        "four_node_convergence_required_before_sdk": True,
        "stdout_is_single_json_document": True,
        "timing_semantics": "single_sample_diagnostic_not_benchmark",
        "stderr_lines": client_stderr,
        "clean_teardown": client["clean_teardown"],
        "receipt_consensus_hash_matched": preimages["receipt_consensus_hash_matched"],
        "block_consensus_hash_matched": preimages["block_consensus_hash_matched"],
        "pbft_commit_signatures_valid": preimages["pbft_commit_signatures_valid"],
        "receipt_verification_ns": preimages["receipt_verification_ns"],
        "block_verification_ns": preimages["block_verification_ns"],
        "pbft_verification_ns": preimages["pbft_verification_ns"],
        "production_publish_verified": client["production_publish_verified"],
        "four_node_qualification": qualified,
    },
    "performance": performance,
    "cleanup": {
        "node_processes_absent": True,
        "listeners_absent": True,
        "host_lock_absent": True,
        "generated_keys_or_certificates_committed": False,
    },
    "raw_client_output": client,
    "results": {
        "initial_block_number": client["initial_block_number"],
        "final_block_number": client["final_block_number"],
        "deployment": transaction(client["deployment"]),
        "event_transaction": transaction(client["event_transaction"], event_match=True),
        "anchor_payload": client.get("anchor_payload"),
        "containing_block": {
            "hash": with_prefix(block["hash"]),
            "transactions_root": with_prefix(block["txsRoot"]),
            "receipts_root": with_prefix(block["receiptsRoot"]),
            "signature_count": len(block["signatureList"]),
            "consensus_hash_matched": preimages["block_consensus_hash_matched"],
        },
        "consensus": {
            "connected_nodes": connected_nodes,
            "sealers": len(client["sealers"]),
            "minimum_required_quorum": consensus["minRequiredQuorum"],
            "maximum_faulty_quorum": consensus["maxFaultyQuorum"],
            "node_ids": [entry["nodeID"] for entry in client["sealers"]],
        },
        "stale_block_limit": client["stale_block_limit"],
        "stale_block_limit_rejected": client["stale_block_limit_rejected"],
        "stale_rejection_error": client.get("stale_rejection_error", ""),
        "qualification": client.get("qualification"),
        "trustdb_qualification": live_qualification,
        "offline_qualification": offline_qualification,
    },
    "client_stderr": client_stderr,
    "limitations": [],
}
if not qualified:
    evidence["limitations"].extend([
        "This run validates the pinned Air node, compiler, C SDK and Go SDK compatibility profile only.",
        "Transaction and receipt proof arrays were retrieved but are not treated as independently verified TrustDB anchor evidence.",
    ])
if raw_fixture:
    evidence["limitations"].insert(
        0,
        "The raw EVM fixture bypasses the pinned Solidity compiler and cannot admit a runtime profile.",
    )
destination = work / f"evidence-{mode}.json"
destination.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(destination.read_text(encoding="utf-8"), end="")
PY
