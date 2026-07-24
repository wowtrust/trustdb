#!/usr/bin/env python3
"""Reproduce or verify the canonical TrustDBAnchorV1 contract artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = REPO_ROOT / "contracts" / "fisco-bcos"
SOURCE = CONTRACT_ROOT / "TrustDBAnchorV1.sol"
CHECKED_ARTIFACTS = CONTRACT_ROOT / "artifacts"
BASELINE = REPO_ROOT / "configs" / "compatibility" / "fisco-bcos-v3.16.3.json"
EXPECTED_VERSIONS = {
    "standard": "Version: 0.8.11+commit.d7f03943.Linux.g++",
    "guomi": "Gm version: 0.8.11+commit.1c3fd7c1.mod.Linux.g++",
}
NATIVE_HASH = {"standard": "keccak256", "guomi": "sm3"}


class BuildError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--platform",
        choices=("linux/amd64",),
        required=True,
        help="canonical build platform; other compiler builds are not artifacts",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        required=True,
        help="verified artifact download cache",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run(command: list[str], cwd: Path = REPO_ROOT) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise BuildError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout


def compiler_pin(mode: str) -> dict[str, object]:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    for artifact in baseline["components"]["solidity"]["artifacts"]:
        if artifact["platform"] == "linux/amd64" and artifact["crypto"] == mode:
            return {
                "release": baseline["components"]["solidity"]["tag"],
                "source_commit": baseline["components"]["solidity"]["commit"],
                "archive": artifact["name"],
                "archive_sha256": artifact["sha256"],
                "version": EXPECTED_VERSIONS[mode],
            }
    raise BuildError(f"missing canonical compiler pin for {mode}")


def extract_compiler_archive(archive: Path, destination: Path) -> Path:
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise BuildError(f"unsafe compiler archive member: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise BuildError(f"unsupported compiler archive member: {member.name}")
        bundle.extractall(destination)
    candidates = [
        path
        for path in destination.rglob("solc*")
        if path.is_file() and not path.name.startswith("._")
    ]
    if len(candidates) != 1:
        raise BuildError(f"compiler archive contains {len(candidates)} candidates")
    candidates[0].chmod(candidates[0].stat().st_mode | 0o111)
    return candidates[0]


def verified_compilers(cache_dir: Path, temporary: Path) -> dict[str, Path]:
    compatibility = REPO_ROOT / "scripts" / "fisco-bcos" / "compatibility.py"
    compilers: dict[str, Path] = {}
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    artifacts = baseline["components"]["solidity"]["artifacts"]
    for mode in ("standard", "guomi"):
        run(
            [
                "python3",
                str(compatibility),
                "verify-artifacts",
                "--platform",
                "linux/amd64",
                "--crypto",
                mode,
                "--cache-dir",
                str(cache_dir.resolve()),
            ]
        )
        artifact = next(
            row
            for row in artifacts
            if row["platform"] == "linux/amd64" and row["crypto"] == mode
        )
        archive = cache_dir.resolve() / "solidity" / artifact["name"]
        if sha256_file(archive) != artifact["sha256"]:
            raise BuildError(f"{mode} compiler archive changed after verification")

        destination = temporary / f"solc-{mode}"
        compilers[mode] = extract_compiler_archive(archive, destination)
    return compilers


def compile_mode(mode: str, compiler: Path, destination: Path) -> dict[str, object]:
    version = run([str(compiler), "--version"]).strip()
    if EXPECTED_VERSIONS[mode] not in version:
        raise BuildError(
            f"{mode} compiler version mismatch: expected "
            f"{EXPECTED_VERSIONS[mode]!r}, got {version!r}"
        )

    output = destination / mode
    output.mkdir(parents=True)
    run(
        [
            str(compiler),
            "--optimize",
            "--optimize-runs",
            "200",
            "--evm-version",
            "london",
            "--metadata-hash",
            "none",
            "--abi",
            "--bin",
            "--bin-runtime",
            "--overwrite",
            "-o",
            str(output),
            str(SOURCE),
        ]
    )

    paths = {
        "abi": output / "TrustDBAnchorV1.abi",
        "creation_bytecode": output / "TrustDBAnchorV1.bin",
        "runtime_bytecode": output / "TrustDBAnchorV1.bin-runtime",
    }
    for label, path in paths.items():
        if not path.is_file() or not path.read_bytes():
            raise BuildError(f"{mode} compiler did not emit {label}")

    native_algorithm = NATIVE_HASH[mode]
    native_hash = run(
        [
            "go",
            "run",
            "./scripts/fisco-bcos/codehash",
            "--algorithm",
            native_algorithm,
            "--hex-file",
            str(paths["runtime_bytecode"]),
        ]
    ).strip()
    creation = bytes.fromhex(paths["creation_bytecode"].read_text().strip())
    runtime = bytes.fromhex(paths["runtime_bytecode"].read_text().strip())
    return {
        "compiler": compiler_pin(mode),
        "abi_sha256": sha256_file(paths["abi"]),
        "creation_bytecode_sha256": sha256_bytes(creation),
        "creation_byte_count": len(creation),
        "runtime_bytecode_sha256": sha256_bytes(runtime),
        "runtime_byte_count": len(runtime),
        "runtime_code_hash_algorithm": native_algorithm,
        "runtime_code_hash": native_hash,
    }


def build(standard: Path, guomi: Path, destination: Path) -> None:
    mode_details = {
        "standard": compile_mode("standard", standard.resolve(), destination),
        "guomi": compile_mode("guomi", guomi.resolve(), destination),
    }
    manifest = {
        "schema": "trustdb.fisco-bcos-contract-artifacts.v1",
        "contract": "TrustDBAnchorV1",
        "payload_version": 1,
        "source": {
            "path": "contracts/fisco-bcos/TrustDBAnchorV1.sol",
            "sha256": sha256_file(SOURCE),
            "license": "Apache-2.0",
        },
        "settings": {
            "solidity": "0.8.11",
            "optimizer": True,
            "optimizer_runs": 200,
            "evm_version": "london",
            "metadata_hash": "none",
        },
        "canonical_event": (
            "AnchorPublished(bytes32,bytes32,uint64,bytes32,bytes32,address,uint16)"
        ),
        "modes": mode_details,
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def compare_trees(expected: Path, actual: Path) -> None:
    expected_files = {
        path.relative_to(expected) for path in expected.rglob("*") if path.is_file()
    }
    actual_files = {
        path.relative_to(actual) for path in actual.rglob("*") if path.is_file()
    }
    if expected_files != actual_files:
        raise BuildError(
            f"artifact file set mismatch: expected {sorted(map(str, expected_files))}, "
            f"got {sorted(map(str, actual_files))}"
        )
    for relative in sorted(expected_files):
        if (expected / relative).read_bytes() != (actual / relative).read_bytes():
            raise BuildError(f"artifact differs: {relative}")


def main() -> int:
    args = parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="trustdb-anchor-contract-") as temp:
            temporary = Path(temp)
            generated = temporary / "artifacts"
            generated.mkdir()
            compilers = verified_compilers(args.cache_dir, temporary)
            build(compilers["standard"], compilers["guomi"], generated)
            if args.check:
                compare_trees(CHECKED_ARTIFACTS, generated)
            else:
                if CHECKED_ARTIFACTS.exists():
                    shutil.rmtree(CHECKED_ARTIFACTS)
                shutil.copytree(generated, CHECKED_ARTIFACTS)
    except (BuildError, OSError, ValueError) as exc:
        print(f"anchor contract build failed: {exc}")
        return 1
    print("TrustDBAnchorV1 artifacts are reproducible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
