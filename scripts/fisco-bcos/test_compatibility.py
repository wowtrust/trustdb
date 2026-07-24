#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("compatibility.py")
SPEC = importlib.util.spec_from_file_location("fisco_compatibility", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
compatibility = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compatibility)


class CompatibilityBaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = compatibility.load_baseline(compatibility.DEFAULT_BASELINE)

    def test_baseline_is_valid(self) -> None:
        compatibility.validate_baseline(self.baseline)

    def test_verified_linux_air_runtime_is_admitted(self) -> None:
        row = compatibility.check_profile(
            self.baseline, "air", "standard", "linux/amd64", "artifact", "native"
        )
        self.assertEqual(row["artifact_status"], "verified")
        row = compatibility.check_profile(
            self.baseline, "air", "standard", "linux/amd64", "runtime", "native"
        )
        self.assertEqual(row["runtime_status"], "verified")

    def test_unverified_linux_arm64_runtime_is_denied(self) -> None:
        with self.assertRaisesRegex(compatibility.BaselineError, "runtime admission denied"):
            compatibility.check_profile(
                self.baseline, "air", "standard", "linux/arm64", "runtime", "native"
            )

    def test_pro_and_max_fail_closed(self) -> None:
        for deployment in ("pro", "max"):
            with self.assertRaisesRegex(compatibility.BaselineError, "artifact admission denied"):
                compatibility.check_profile(
                    self.baseline, deployment, "guomi", "linux/arm64", "artifact", "native"
                )

    def test_container_without_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(compatibility.BaselineError, "container admission denied"):
            compatibility.check_profile(
                self.baseline, "air", "standard", "linux/amd64", "documented", "container"
            )

    def test_unavailable_artifact_cannot_be_runtime_candidate(self) -> None:
        invalid = copy.deepcopy(self.baseline)
        row = next(item for item in invalid["matrix"] if item["deployment"] == "pro")
        row["runtime_status"] = "partial"
        with self.assertRaisesRegex(compatibility.BaselineError, "must be unsupported"):
            compatibility.validate_baseline(invalid)

    def test_raw_evm_diagnostic_cannot_promote_runtime(self) -> None:
        invalid = copy.deepcopy(self.baseline)
        row = next(
            item
            for item in invalid["matrix"]
            if item["deployment"] == "air"
            and item["crypto"] == "standard"
            and item["platform"] == "darwin/arm64"
        )
        row["runtime_status"] = "verified"
        row["evidence"] = (
            "docs/integrations/evidence/fisco-bcos/"
            "2026-07-24-darwin-arm64-standard-diagnostic.json"
        )
        with self.assertRaisesRegex(compatibility.BaselineError, "raw-EVM diagnostic"):
            compatibility.validate_baseline(invalid)

    def test_verified_runtime_requires_committed_evidence(self) -> None:
        invalid = copy.deepcopy(self.baseline)
        row = next(
            item
            for item in invalid["matrix"]
            if item["deployment"] == "air"
            and item["crypto"] == "standard"
            and item["platform"] == "linux/amd64"
        )
        row["runtime_status"] = "verified"
        row.pop("evidence", None)
        with self.assertRaisesRegex(compatibility.BaselineError, "requires committed evidence"):
            compatibility.validate_baseline(invalid)

    def test_verified_runtime_requires_clean_teardown(self) -> None:
        invalid = copy.deepcopy(self.baseline)
        row = next(item for item in invalid["matrix"] if item["runtime_status"] == "verified")
        evidence_path = compatibility.REPO_ROOT / row["evidence"]
        original = compatibility.load_baseline(evidence_path)
        for section, field, message in (
            ("harness_validation", "clean_teardown", "clean structured harness output"),
            ("cleanup", "node_processes_absent", "clean host teardown"),
            ("raw_client_output", "clean_teardown", "clean raw client output"),
        ):
            evidence = copy.deepcopy(original)
            evidence[section][field] = False
            with self.subTest(section=section, field=field):
                with mock.patch.object(compatibility, "load_baseline", return_value=evidence):
                    with self.assertRaisesRegex(compatibility.BaselineError, message):
                        compatibility.validate_baseline(invalid)

    def test_verified_runtime_requires_pinned_compiler_source(self) -> None:
        invalid = copy.deepcopy(self.baseline)
        row = next(
            item
            for item in invalid["matrix"]
            if item["deployment"] == "air"
            and item["crypto"] == "standard"
            and item["platform"] == "darwin/arm64"
        )
        evidence_path = compatibility.REPO_ROOT / row["evidence"]
        evidence = compatibility.load_baseline(evidence_path)
        evidence["probe_source"] = "untracked-compiler"
        original_loader = compatibility.load_baseline

        def load(path: Path) -> dict:
            if path == evidence_path:
                return evidence
            return original_loader(path)

        with mock.patch.object(compatibility, "load_baseline", side_effect=load):
            with self.assertRaisesRegex(
                compatibility.BaselineError, "requires the pinned compiler source"
            ):
                compatibility.validate_baseline(invalid)

    def test_evidence_must_match_exact_artifact_digest_set(self) -> None:
        invalid = copy.deepcopy(self.baseline)
        row = next(item for item in invalid["matrix"] if item.get("evidence"))
        evidence_path = compatibility.REPO_ROOT / row["evidence"]
        evidence = compatibility.load_baseline(evidence_path)
        evidence["artifacts"] = dict(evidence["artifacts"])
        artifact_name = next(iter(evidence["artifacts"]))
        evidence["artifacts"][artifact_name] = "0" * 64
        with mock.patch.object(compatibility, "load_baseline", return_value=evidence):
            with self.assertRaisesRegex(compatibility.BaselineError, "artifact digest set mismatch"):
                compatibility.validate_baseline(invalid)

    def test_corrupt_cache_is_replaced_only_when_downloads_are_allowed(self) -> None:
        expected = b"pinned artifact bytes"
        artifact = {
            "platform": "linux/amd64",
            "name": "artifact.bin",
            "url": "https://example.invalid/artifact.bin",
            "size": len(expected),
            "sha256": hashlib.sha256(expected).hexdigest(),
        }
        baseline = {
            "components": {
                "node": {"artifacts": [artifact]},
                "c_sdk": {"artifacts": []},
                "solidity": {"artifacts": []},
                "tassl": {"artifacts": []},
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            cached = cache / "node" / artifact["name"]
            cached.parent.mkdir(parents=True)
            cached.write_bytes(b"truncated")
            with self.assertRaisesRegex(compatibility.BaselineError, "size mismatch"):
                compatibility.verify_artifacts(
                    baseline, cache, "linux/amd64", None, no_download=True
                )

            def replace(_url: str, destination: Path) -> None:
                destination.write_bytes(expected)

            with mock.patch.object(compatibility, "download", side_effect=replace):
                result = compatibility.verify_artifacts(
                    baseline, cache, "linux/amd64", None, no_download=False
                )
            self.assertEqual(cached.read_bytes(), expected)
            self.assertEqual(result[0]["status"], "verified")


if __name__ == "__main__":
    unittest.main()
