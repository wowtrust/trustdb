#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import tempfile
import unittest
import urllib.error
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

    def test_transient_download_failures_retry_until_success(self) -> None:
        url = "https://example.invalid/artifact.bin"
        payload = b"pinned artifact bytes"
        failures = [
            urllib.error.HTTPError(url, 429, "Too Many Requests", {}, None),
            urllib.error.HTTPError(url, 504, "Gateway Timeout", {}, None),
            urllib.error.URLError(TimeoutError("timed out")),
        ]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "artifact.bin"
            with (
                mock.patch.object(
                    compatibility.urllib.request,
                    "urlopen",
                    side_effect=[*failures, io.BytesIO(payload)],
                ) as urlopen,
                mock.patch.object(compatibility.time, "sleep") as sleep,
            ):
                compatibility.download(url, destination)

            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(urlopen.call_count, compatibility.DOWNLOAD_ATTEMPTS)
            self.assertEqual(
                [call.kwargs["timeout"] for call in urlopen.call_args_list],
                [compatibility.DOWNLOAD_TIMEOUT_SECONDS] * compatibility.DOWNLOAD_ATTEMPTS,
            )
            self.assertEqual(
                [call.args[0] for call in sleep.call_args_list],
                [1, 2, 4],
            )

    def test_transient_download_failure_exhausts_bounded_attempts(self) -> None:
        url = "https://example.invalid/artifact.bin"
        failures = [
            urllib.error.HTTPError(url, 504, "Gateway Timeout", {}, None)
            for _ in range(compatibility.DOWNLOAD_ATTEMPTS)
        ]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "artifact.bin"
            with (
                mock.patch.object(
                    compatibility.urllib.request, "urlopen", side_effect=failures
                ) as urlopen,
                mock.patch.object(compatibility.time, "sleep") as sleep,
                self.assertRaisesRegex(urllib.error.HTTPError, "Gateway Timeout"),
            ):
                compatibility.download(url, destination)

            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_suffix(".bin.part").exists())
            self.assertEqual(urlopen.call_count, compatibility.DOWNLOAD_ATTEMPTS)
            self.assertEqual(sleep.call_count, compatibility.DOWNLOAD_ATTEMPTS - 1)

    def test_non_transient_http_error_is_not_retried(self) -> None:
        url = "https://example.invalid/artifact.bin"
        failure = urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "artifact.bin"
            with (
                mock.patch.object(
                    compatibility.urllib.request, "urlopen", side_effect=failure
                ) as urlopen,
                mock.patch.object(compatibility.time, "sleep") as sleep,
                self.assertRaisesRegex(urllib.error.HTTPError, "Not Found"),
            ):
                compatibility.download(url, destination)

            urlopen.assert_called_once()
            sleep.assert_not_called()

    def test_downloaded_checksum_mismatch_fails_without_retry(self) -> None:
        expected = b"expected"
        corrupt = b"corrupt!"
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
            with (
                mock.patch.object(
                    compatibility.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(corrupt),
                ) as urlopen,
                mock.patch.object(compatibility.time, "sleep") as sleep,
                self.assertRaisesRegex(compatibility.BaselineError, "sha256 mismatch"),
            ):
                compatibility.verify_artifacts(
                    baseline,
                    Path(directory),
                    "linux/amd64",
                    None,
                    no_download=False,
                )

            urlopen.assert_called_once()
            sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
