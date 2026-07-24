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
ROOT_SM_CERT_WAS_PRESENT=false
ROOT_SM_PARAM_WAS_PRESENT=false
[[ -e ${REPO_ROOT}/sm_cert.cnf ]] && ROOT_SM_CERT_WAS_PRESENT=true
[[ -e ${REPO_ROOT}/sm_sm2.param ]] && ROOT_SM_PARAM_WAS_PRESENT=true

usage() {
    echo "usage: $0 --mode standard|guomi --work-dir DIR [--cache-dir DIR] [--raw-evm-fixture] [--p2p-port PORT] [--rpc-port PORT]" >&2
}

while (($#)); do
    case "$1" in
        --mode) MODE=$2; shift 2 ;;
        --work-dir) WORK_DIR=$2; shift 2 ;;
        --cache-dir) CACHE_DIR_ARG=$2; shift 2 ;;
        --p2p-port) P2P_PORT=$2; shift 2 ;;
        --rpc-port) RPC_PORT=$2; shift 2 ;;
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
export HOME="${WORK_DIR}/home"

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
    -a "${ADMIN_ADDRESS}"
)
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
export CGO_LDFLAGS="-L$(dirname "${CSDK_ARCHIVE}")"
if [[ ${PLATFORM} == darwin/* ]]; then
    export DYLD_LIBRARY_PATH="$(dirname "${CSDK_ARCHIVE}")${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"
else
    export LD_LIBRARY_PATH="$(dirname "${CSDK_ARCHIVE}")${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
fi

(
    cd "${SCRIPT_DIR}/smoke-client"
    GOWORK=off go build -trimpath -o "${WORK_DIR}/smoke-client" .
)

NODE_PIDS=()

stop_nodes() {
    local pid
    local attempt
    local running

    for ((index=${#NODE_PIDS[@]} - 1; index >= 0; index--)); do
        pid=${NODE_PIDS[index]}
        kill -TERM "${pid}" 2>/dev/null || true
    done

    for attempt in {1..60}; do
        running=false
        for pid in "${NODE_PIDS[@]}"; do
            if kill -0 "${pid}" 2>/dev/null; then
                running=true
                break
            fi
        done
        [[ ${running} == false ]] && return 0
        sleep 0.5
    done

    for pid in "${NODE_PIDS[@]}"; do
        kill -KILL "${pid}" 2>/dev/null || true
    done
    return 1
}

cleanup() {
    stop_nodes >/dev/null 2>&1 || true
    if [[ -n ${SMOKE_LOCK:-} ]]; then
        rm -f "${SMOKE_LOCK}/pid"
        rmdir "${SMOKE_LOCK}" 2>/dev/null || true
    fi
}
SMOKE_LOCK="${TMPDIR:-/tmp}/trustdb-fisco-bcos-smoke-${PLATFORM//\//-}.lock"
if ! mkdir "${SMOKE_LOCK}" 2>/dev/null; then
    echo "another FISCO BCOS smoke owns ${SMOKE_LOCK}; standard and Guomi runs must be sequential" >&2
    exit 1
fi
printf '%s\n' "$$" >"${SMOKE_LOCK}/pid"
trap cleanup EXIT INT TERM

# The generated start scripts identify a process only by the shared node
# executable path. They therefore cannot safely start these four nodes in
# sequence, while starting all four at once has exposed an upstream gateway
# race on high-core Linux hosts. Own the exact PID of every node instead.
for index in 0 1 2 3; do
    node_dir="${NODE_PARENT}/node${index}"
    : >"${node_dir}/nohup.out"
    (
        cd "${node_dir}"
        nohup ../fisco-bcos -c config.ini -g config.genesis >>nohup.out 2>&1 &
        printf '%s\n' "$!" >.trustdb-smoke.pid
    )
    pid=$(<"${node_dir}/.trustdb-smoke.pid")
    NODE_PIDS+=("${pid}")

    ready=false
    for attempt in {1..40}; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "node${index} exited during startup" >&2
            tail -80 "${node_dir}/nohup.out" >&2
            exit 1
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
        exit 1
    fi
    printf 'node%s pid=%s ready\n' "${index}" "${pid}" >>"${WORK_DIR}/node-start.log"
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
python3 "${WAIT_AIR_READY}" \
    --node-parent "${NODE_PARENT}" --node-count 4 --timeout-seconds 30

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
)
if [[ ${RAW_EVM_FIXTURE} == true ]]; then
    CLIENT_ARGS+=(--raw-evm-fixture)
else
    CLIENT_ARGS+=(
        --abi "${WORK_DIR}/contract/CompatibilityProbe.abi"
        --bin "${WORK_DIR}/contract/CompatibilityProbe.bin"
    )
fi
(
    cd "${WORK_DIR}"
    "${WORK_DIR}/smoke-client" "${CLIENT_ARGS[@]}"
) >"${WORK_DIR}/client-evidence.json" \
  2>"${WORK_DIR}/client-stderr.log"

if ! stop_nodes; then
    echo "one or more FISCO BCOS nodes required SIGKILL during teardown" >&2
    exit 1
fi
NODE_PIDS=()

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

rm -f "${SMOKE_LOCK}/pid"
rmdir "${SMOKE_LOCK}"
SMOKE_LOCK=""

if [[ ${ROOT_SM_CERT_WAS_PRESENT} == false && -e ${REPO_ROOT}/sm_cert.cnf ]] || \
   [[ ${ROOT_SM_PARAM_WAS_PRESENT} == false && -e ${REPO_ROOT}/sm_sm2.param ]]; then
    echo "smoke subprocess polluted the repository root with TASSL helper files" >&2
    exit 1
fi

python3 - "${WORK_DIR}" "${BASELINE}" "${MODE}" "${PLATFORM}" "${SOLC_EXECUTABLE}" \
    "${CACHE_DIR}" "${P2P_PORT}" "${RPC_PORT}" "${RAW_EVM_FIXTURE}" <<'PY'
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
) = sys.argv[2:]
client = json.loads((work / "client-evidence.json").read_text(encoding="utf-8"))
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
raw_fixture = raw_evm_fixture == "true"
command = [
    "scripts/fisco-bcos/smoke-air.sh",
    "--mode", mode,
    "--work-dir", str(work),
    "--cache-dir", cache_dir,
    "--p2p-port", p2p_port,
    "--rpc-port", rpc_port,
]
if raw_fixture:
    command.append("--raw-evm-fixture")

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
        "stderr_lines": client_stderr,
        "clean_teardown": client["clean_teardown"],
    },
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
        "containing_block": {
            "hash": with_prefix(block["hash"]),
            "transactions_root": with_prefix(block["txsRoot"]),
            "receipts_root": with_prefix(block["receiptsRoot"]),
            "signature_count": len(block["signatureList"]),
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
    },
    "client_stderr": client_stderr,
    "limitations": [
        "This run validates the pinned Air node, compiler, C SDK and Go SDK compatibility profile only.",
        "Transaction and receipt proof arrays were retrieved but are not treated as independently verified TrustDB anchor evidence.",
    ],
}
if raw_fixture:
    evidence["limitations"].insert(
        0,
        "The raw EVM fixture bypasses the pinned Solidity compiler and cannot admit a runtime profile.",
    )
destination = work / f"evidence-{mode}.json"
destination.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(destination.read_text(encoding="utf-8"), end="")
PY
