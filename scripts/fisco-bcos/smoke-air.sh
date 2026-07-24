#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)
BASELINE="${REPO_ROOT}/configs/compatibility/fisco-bcos-v3.16.3.json"
COMPAT="${SCRIPT_DIR}/compatibility.py"
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

cleanup() {
    bash "${NODE_PARENT}/stop_all.sh" >/dev/null 2>&1 || true
    rm -f "${SMOKE_LOCK}/pid"
    rmdir "${SMOKE_LOCK}" 2>/dev/null || true
}
SMOKE_LOCK="${TMPDIR:-/tmp}/trustdb-fisco-bcos-smoke-${PLATFORM//\//-}.lock"
if ! mkdir "${SMOKE_LOCK}" 2>/dev/null; then
    echo "another FISCO BCOS smoke owns ${SMOKE_LOCK}; standard and Guomi runs must be sequential" >&2
    exit 1
fi
printf '%s\n' "$$" >"${SMOKE_LOCK}/pid"
trap cleanup EXIT INT TERM
bash "${NODE_PARENT}/start_all.sh" >"${WORK_DIR}/node-start.log" 2>&1
# The node process can be alive before its RPC service completes initialization.
# A fixed, bounded readiness window avoids retrying DialContext, whose upstream
# error path does not expose a native SDK handle that callers can destroy.
sleep 10

for index in 0 1 2 3; do
    if ! pgrep -f "${NODE_PARENT}/node${index}/../fisco-bcos" >/dev/null 2>&1; then
        echo "node${index} is not running" >&2
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

if [[ ${ROOT_SM_CERT_WAS_PRESENT} == false && -e ${REPO_ROOT}/sm_cert.cnf ]] || \
   [[ ${ROOT_SM_PARAM_WAS_PRESENT} == false && -e ${REPO_ROOT}/sm_sm2.param ]]; then
    echo "smoke subprocess polluted the repository root with TASSL helper files" >&2
    exit 1
fi

python3 - "${WORK_DIR}" "${BASELINE}" "${MODE}" "${PLATFORM}" "${SOLC_EXECUTABLE}" <<'PY'
import json
import platform
import sys
from pathlib import Path

work = Path(sys.argv[1])
baseline_path, mode, target_platform, compiler_executable = sys.argv[2:]
client = json.loads((work / "client-evidence.json").read_text(encoding="utf-8"))
artifacts = json.loads((work / "artifact-verification.json").read_text(encoding="utf-8"))
client["environment"] = {
    "platform": target_platform,
    "host_platform": platform.platform(),
    "python": platform.python_version(),
    "node_version": (work / "node-version.txt").read_text(encoding="utf-8"),
    "solc_version": (work / "solc-version.txt").read_text(encoding="utf-8"),
    "tassl_version": (work / "tassl-version.txt").read_text(encoding="utf-8"),
    "compiler_executable": compiler_executable == "true",
}
client["artifacts"] = artifacts["artifacts"]
client["certificate_verification"] = (work / "certificate-verification.txt").read_text(encoding="utf-8").splitlines()
client["client_stderr"] = (work / "client-stderr.log").read_text(encoding="utf-8").splitlines()
client["baseline_file"] = str(Path(baseline_path).resolve())
client["mode"] = mode
destination = work / f"evidence-{mode}.json"
destination.write_text(json.dumps(client, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(destination.read_text(encoding="utf-8"), end="")
PY
