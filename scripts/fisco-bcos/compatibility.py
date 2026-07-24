#!/usr/bin/env python3
"""Validate and enforce the pinned FISCO BCOS compatibility baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = (
    REPO_ROOT / "configs" / "compatibility" / "fisco-bcos-v3.16.3.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PLATFORMS = {"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"}
CRYPTO_MODES = {"standard", "guomi"}
DEPLOYMENTS = {"air", "pro", "max"}
ARTIFACT_STATES = {"verified", "unavailable"}
RUNTIME_STATES = {"verified", "partial", "unverified", "unsupported"}


class BaselineError(Exception):
    pass


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot load baseline {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BaselineError("baseline root must be an object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineError(message)


def validate_artifact(component: str, artifact: dict[str, Any]) -> None:
    prefix = f"components.{component}.artifacts"
    require(artifact.get("platform") in PLATFORMS, f"{prefix}: invalid platform")
    require(isinstance(artifact.get("name"), str) and artifact["name"], f"{prefix}: missing name")
    require(
        isinstance(artifact.get("url"), str) and artifact["url"].startswith("https://"),
        f"{prefix}.{artifact.get('name')}: invalid URL",
    )
    require(
        isinstance(artifact.get("size"), int) and artifact["size"] > 0,
        f"{prefix}.{artifact.get('name')}: invalid size",
    )
    require(
        isinstance(artifact.get("sha256"), str) and SHA256_RE.fullmatch(artifact["sha256"]) is not None,
        f"{prefix}.{artifact.get('name')}: invalid sha256",
    )
    if component == "solidity":
        require(artifact.get("crypto") in CRYPTO_MODES, f"{prefix}: invalid crypto mode")


def validate_evidence(
    baseline: dict[str, Any], row: dict[str, Any], evidence_reference: str
) -> None:
    relative = Path(evidence_reference)
    require(
        not relative.is_absolute() and ".." not in relative.parts,
        f"matrix evidence path must be repository-relative: {evidence_reference}",
    )
    evidence_path = REPO_ROOT / relative
    try:
        evidence = load_baseline(evidence_path)
    except BaselineError as exc:
        raise BaselineError(f"invalid matrix evidence {evidence_reference}: {exc}") from exc
    key = (row["deployment"], row["crypto"], row["platform"])
    require(evidence.get("schema_version") == 1, f"evidence {key} schema mismatch")
    require(
        evidence.get("baseline_id") == baseline["baseline_id"],
        f"evidence {key} baseline mismatch",
    )
    require(
        evidence.get("profile")
        == {
            "deployment": row["deployment"],
            "crypto": row["crypto"],
            "platform": row["platform"],
        },
        f"evidence {key} profile mismatch",
    )
    admitted = evidence.get("admitted")
    require(isinstance(admitted, bool), f"evidence {key} requires boolean admitted")
    require(
        isinstance(evidence.get("command"), str) and evidence["command"],
        f"evidence {key} requires the exact smoke command",
    )
    require(
        isinstance(evidence.get("host"), str) and evidence["host"],
        f"evidence {key} requires the host platform",
    )
    require(
        evidence.get("node_commit") == baseline["components"]["node"]["commit"],
        f"evidence {key} node commit mismatch",
    )
    require(
        evidence.get("node_version")
        == baseline["components"]["node"]["tag"].removeprefix("v"),
        f"evidence {key} node version mismatch",
    )
    require(
        evidence.get("sm_crypto") is (row["crypto"] == "guomi"),
        f"evidence {key} negotiated crypto mode mismatch",
    )

    pins = evidence.get("pins")
    expected_pins = {
        "node": f"{baseline['components']['node']['tag']}@{baseline['components']['node']['commit']}",
        "go_sdk": f"{baseline['components']['go_sdk']['tag']}@{baseline['components']['go_sdk']['commit']}",
        "c_sdk_source": baseline["components"]["go_sdk"]["c_sdk_module"]["commit"],
        "c_sdk_native": f"{baseline['components']['c_sdk']['tag']}@{baseline['components']['c_sdk']['commit']}",
        "solidity": f"{baseline['components']['solidity']['tag']}@{baseline['components']['solidity']['commit']}",
        "tassl": f"{baseline['components']['tassl']['tag']}@{baseline['components']['tassl']['commit']}",
    }
    require(pins == expected_pins, f"evidence {key} component pins mismatch")

    expected_artifacts = {
        artifact["name"]: artifact["sha256"]
        for _component, artifact in iter_artifacts(
            baseline, row["platform"], row["crypto"]
        )
    }
    require(
        evidence.get("artifacts") == expected_artifacts,
        f"evidence {key} artifact digest set mismatch",
    )

    results = evidence.get("results")
    require(isinstance(results, dict), f"evidence {key} requires runtime results")
    deployment = results.get("deployment")
    event_transaction = results.get("event_transaction")
    containing_block = results.get("containing_block")
    consensus = results.get("consensus")
    for label, transaction in (
        ("deployment", deployment),
        ("event transaction", event_transaction),
    ):
        require(isinstance(transaction, dict), f"evidence {key} lacks {label}")
        require(transaction.get("status") == 0, f"evidence {key} {label} failed")
        require(
            isinstance(transaction.get("transaction_hash"), str)
            and transaction["transaction_hash"].startswith("0x")
            and len(transaction["transaction_hash"]) == 66,
            f"evidence {key} {label} hash is invalid",
        )
        require(
            isinstance(transaction.get("transaction_proof"), list)
            and transaction["transaction_proof"],
            f"evidence {key} {label} transaction proof is absent",
        )
        require(
            isinstance(transaction.get("receipt_proof"), list)
            and transaction["receipt_proof"],
            f"evidence {key} {label} receipt proof is absent",
        )
    require(
        event_transaction.get("event_transaction_match") is True,
        f"evidence {key} event is not bound to the submitted transaction",
    )
    require(isinstance(containing_block, dict), f"evidence {key} lacks containing block")
    for field in ("hash", "transactions_root", "receipts_root"):
        require(
            isinstance(containing_block.get(field), str)
            and containing_block[field].startswith("0x")
            and len(containing_block[field]) == 66,
            f"evidence {key} containing block {field} is invalid",
        )
    require(
        isinstance(containing_block.get("signature_count"), int)
        and containing_block["signature_count"] >= 3,
        f"evidence {key} lacks PBFT block signatures",
    )
    require(isinstance(consensus, dict), f"evidence {key} lacks consensus metadata")
    require(consensus.get("connected_nodes") == 4, f"evidence {key} node count mismatch")
    require(consensus.get("sealers") == 4, f"evidence {key} sealer count mismatch")
    require(
        consensus.get("minimum_required_quorum") == 3,
        f"evidence {key} quorum mismatch",
    )
    node_ids = consensus.get("node_ids")
    require(
        isinstance(node_ids, list)
        and len(node_ids) == 4
        and all(isinstance(node_id, str) and node_id for node_id in node_ids)
        and len(set(node_ids)) == 4,
        f"evidence {key} requires four unique node identities",
    )
    require(
        results.get("stale_block_limit_rejected") is True,
        f"evidence {key} did not reject stale blockLimit",
    )
    if evidence.get("probe_source") == "compiler-independent-raw-evm-log0":
        require(
            row["runtime_status"] != "verified",
            f"raw-EVM diagnostic cannot verify runtime row {key}",
        )
    if row["runtime_status"] == "verified":
        require(
            evidence.get("evidence_class") == "runtime_verified",
            f"verified runtime row {key} requires runtime_verified evidence",
        )
        require(
            evidence.get("compiler_executable") is True,
            f"verified runtime row {key} requires the pinned compiler",
        )
        require(
            evidence.get("probe_source") == "pinned-solidity-compiler",
            f"verified runtime row {key} requires the pinned compiler source",
        )
        require(
            bool(evidence.get("certificate_verification")),
            f"verified runtime row {key} requires certificate verification",
        )
        harness_validation = evidence.get("harness_validation")
        require(
            isinstance(harness_validation, dict)
            and harness_validation.get("four_node_convergence_required_before_sdk") is True
            and harness_validation.get("stdout_is_single_json_document") is True
            and harness_validation.get("stderr_lines") == []
            and harness_validation.get("clean_teardown") is True,
            f"verified runtime row {key} requires clean structured harness output",
        )
        cleanup = evidence.get("cleanup")
        require(
            isinstance(cleanup, dict)
            and cleanup.get("node_processes_absent") is True
            and cleanup.get("listeners_absent") is True
            and cleanup.get("host_lock_absent") is True
            and cleanup.get("generated_keys_or_certificates_committed") is False,
            f"verified runtime row {key} requires clean host teardown",
        )
        raw_client_output = evidence.get("raw_client_output")
        require(
            isinstance(raw_client_output, dict)
            and raw_client_output.get("clean_teardown") is True,
            f"verified runtime row {key} requires clean raw client output",
        )
    require(
        admitted == (row["runtime_status"] == "verified"),
        f"evidence {key} admission disagrees with runtime_status",
    )


def validate_baseline(value: dict[str, Any]) -> None:
    require(value.get("schema_version") == 1, "unsupported schema_version")
    policy = value.get("policy")
    require(isinstance(policy, dict) and policy.get("fail_closed") is True, "policy.fail_closed must be true")
    require(policy.get("default_admission_level") == "runtime", "default admission must be runtime")

    components = value.get("components")
    require(isinstance(components, dict), "components must be an object")
    for name in ("node", "go_sdk", "c_sdk", "solidity", "tassl", "documentation"):
        require(isinstance(components.get(name), dict), f"missing component {name}")
    for name in ("node", "go_sdk", "c_sdk", "solidity", "tassl"):
        require(COMMIT_RE.fullmatch(components[name].get("commit", "")) is not None, f"invalid {name} commit")
    require(
        COMMIT_RE.fullmatch(components["documentation"].get("commit", "")) is not None,
        "invalid documentation commit",
    )
    require(components["node"].get("container", {}).get("status") == "unavailable", "v3.16.3 container must remain unavailable")
    require(components["node"].get("container", {}).get("digest") is None, "unavailable container must not have a digest")

    artifact_keys: set[tuple[str, str, str]] = set()
    for component in ("node", "c_sdk", "solidity", "tassl"):
        artifacts = components[component].get("artifacts")
        require(isinstance(artifacts, list) and artifacts, f"{component} artifacts must be non-empty")
        for artifact in artifacts:
            require(isinstance(artifact, dict), f"{component} artifact must be an object")
            validate_artifact(component, artifact)
            key = (component, artifact["platform"], artifact["name"])
            require(key not in artifact_keys, f"duplicate artifact {key}")
            artifact_keys.add(key)

    capabilities = value.get("required_capabilities")
    require(isinstance(capabilities, list) and capabilities, "required_capabilities must be non-empty")
    require(len(set(capabilities)) == len(capabilities), "required_capabilities contains duplicates")

    matrix = value.get("matrix")
    require(isinstance(matrix, list) and matrix, "matrix must be non-empty")
    matrix_keys: set[tuple[str, str, str]] = set()
    for row in matrix:
        require(isinstance(row, dict), "matrix row must be an object")
        deployment = row.get("deployment")
        crypto = row.get("crypto")
        platform = row.get("platform")
        require(deployment in DEPLOYMENTS, f"invalid deployment {deployment}")
        require(crypto in CRYPTO_MODES, f"invalid crypto mode {crypto}")
        require(platform in PLATFORMS, f"invalid matrix platform {platform}")
        require(row.get("artifact_status") in ARTIFACT_STATES, "invalid artifact_status")
        require(row.get("runtime_status") in RUNTIME_STATES, "invalid runtime_status")
        require(isinstance(row.get("reason"), str) and row["reason"], "matrix row requires a reason")
        key = (deployment, crypto, platform)
        require(key not in matrix_keys, f"duplicate matrix row {key}")
        matrix_keys.add(key)
        if row["runtime_status"] == "verified":
            require(row["artifact_status"] == "verified", f"runtime row {key} lacks verified artifacts")
        if row["artifact_status"] == "unavailable":
            require(row["runtime_status"] == "unsupported", f"unavailable row {key} must be unsupported")
        evidence_reference = row.get("evidence")
        if row["runtime_status"] == "verified":
            require(
                isinstance(evidence_reference, str) and evidence_reference,
                f"verified runtime row {key} requires committed evidence",
            )
        if evidence_reference is not None:
            require(
                isinstance(evidence_reference, str) and evidence_reference,
                f"matrix evidence reference {key} must be a non-empty string",
            )
            validate_evidence(value, row, evidence_reference)

    for deployment in DEPLOYMENTS:
        for crypto in CRYPTO_MODES:
            for platform in ("linux/amd64", "linux/arm64"):
                require((deployment, crypto, platform) in matrix_keys, f"missing matrix row {(deployment, crypto, platform)}")


def find_profile(
    value: dict[str, Any], deployment: str, crypto: str, platform: str
) -> dict[str, Any]:
    matches = [
        row
        for row in value["matrix"]
        if row["deployment"] == deployment
        and row["crypto"] == crypto
        and row["platform"] == platform
    ]
    if len(matches) != 1:
        raise BaselineError(
            f"profile {deployment}/{crypto}/{platform} is not uniquely pinned"
        )
    return matches[0]


def check_profile(
    value: dict[str, Any],
    deployment: str,
    crypto: str,
    platform: str,
    level: str,
    distribution: str,
) -> dict[str, Any]:
    if distribution == "container":
        container = value["components"]["node"]["container"]
        if container["status"] != "verified" or not container.get("digest"):
            raise BaselineError(
                f"container admission denied: {container['reference']} has no pinned digest"
            )
    row = find_profile(value, deployment, crypto, platform)
    if level == "artifact" and row["artifact_status"] != "verified":
        raise BaselineError(
            f"artifact admission denied for {deployment}/{crypto}/{platform}: {row['reason']}"
        )
    if level == "runtime" and row["runtime_status"] != "verified":
        raise BaselineError(
            f"runtime admission denied for {deployment}/{crypto}/{platform}: "
            f"status={row['runtime_status']}; {row['reason']}"
        )
    return row


def iter_artifacts(
    value: dict[str, Any], platform: str | None, crypto: str | None
) -> Iterable[tuple[str, dict[str, Any]]]:
    for component in ("node", "c_sdk", "solidity", "tassl"):
        for artifact in value["components"][component]["artifacts"]:
            if platform is not None and artifact["platform"] != platform:
                continue
            if crypto is not None and component == "solidity" and artifact["crypto"] != crypto:
                continue
            yield component, artifact


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, artifact: dict[str, Any]) -> None:
    actual_size = path.stat().st_size
    if actual_size != artifact["size"]:
        raise BaselineError(
            f"size mismatch for {path}: expected {artifact['size']}, got {actual_size}"
        )
    actual_sha256 = hash_file(path)
    if actual_sha256 != artifact["sha256"]:
        raise BaselineError(
            f"sha256 mismatch for {path}: expected {artifact['sha256']}, got {actual_sha256}"
        )


def download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "trustdb-fisco-compat/1"})
    try:
        with urllib.request.urlopen(request) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def verify_artifacts(
    value: dict[str, Any], cache_dir: Path, platform: str | None, crypto: str | None, no_download: bool
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    selected = list(iter_artifacts(value, platform, crypto))
    if not selected:
        raise BaselineError("no artifacts match the requested platform/crypto filters")
    for component, artifact in selected:
        path = cache_dir / component / artifact["name"]
        if path.exists():
            try:
                verify_file(path, artifact)
            except BaselineError:
                if no_download:
                    raise
                path.unlink()
                download(artifact["url"], path)
                verify_file(path, artifact)
        else:
            if no_download:
                raise BaselineError(f"artifact is not cached: {path}")
            download(artifact["url"], path)
            verify_file(path, artifact)
        results.append(
            {
                "component": component,
                "name": artifact["name"],
                "sha256": artifact["sha256"],
                "status": "verified",
            }
        )
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate", help="validate the baseline schema and fail-closed invariants")

    check = subparsers.add_parser("check", help="admit one exact compatibility profile")
    check.add_argument("--deployment", required=True, choices=sorted(DEPLOYMENTS))
    check.add_argument("--crypto", required=True, choices=sorted(CRYPTO_MODES))
    check.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    check.add_argument("--level", choices=("documented", "artifact", "runtime"), default="runtime")
    check.add_argument("--distribution", choices=("native", "container"), default="native")

    verify = subparsers.add_parser("verify-artifacts", help="download/cache and verify pinned artifacts")
    verify.add_argument("--cache-dir", required=True, type=Path)
    verify.add_argument("--platform", choices=sorted(PLATFORMS))
    verify.add_argument("--crypto", choices=sorted(CRYPTO_MODES))
    verify.add_argument("--no-download", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        value = load_baseline(args.baseline)
        validate_baseline(value)
        if args.command == "validate":
            result: Any = {"baseline_id": value["baseline_id"], "status": "valid"}
        elif args.command == "check":
            row = check_profile(
                value,
                args.deployment,
                args.crypto,
                args.platform,
                args.level,
                args.distribution,
            )
            result = {"baseline_id": value["baseline_id"], "admitted": True, "profile": row}
        elif args.command == "verify-artifacts":
            result = {
                "baseline_id": value["baseline_id"],
                "artifacts": verify_artifacts(
                    value, args.cache_dir, args.platform, args.crypto, args.no_download
                ),
            }
        else:
            raise AssertionError(f"unhandled command {args.command}")
    except (BaselineError, OSError, urllib.error.URLError) as exc:
        print(f"compatibility check failed: {exc}", file=sys.stderr)
        return 1
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
