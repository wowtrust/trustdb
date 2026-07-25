#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("wait_air_ready.py")
SPEC = importlib.util.spec_from_file_location("fisco_wait_air_ready", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)


class AirReadinessTest(unittest.TestCase):
    def test_empty_or_unrelated_logs_report_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory) / "node0" / "log"
            log_dir.mkdir(parents=True)
            (log_dir / "log_empty.log").write_text("", encoding="utf-8")
            (log_dir / "log_unrelated.log").write_text(
                "node process started\n", encoding="utf-8"
            )

            self.assertEqual(
                readiness.observed_connected_nodes(Path(directory) / "node0"), 0
            )

    def test_observation_uses_the_maximum_across_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory) / "node0" / "log"
            log_dir.mkdir(parents=True)
            (log_dir / "log_first.log").write_text(
                "notifyGroupNodeInfo,connectedNodeSize=2\n", encoding="utf-8"
            )
            (log_dir / "log_second.log").write_text(
                "notifyGroupNodeInfo,connectedNodeSize=1\n"
                "notifyGroupNodeInfo,connectedNodeSize=4\n",
                encoding="utf-8",
            )

            self.assertEqual(
                readiness.observed_connected_nodes(Path(directory) / "node0"), 4
            )

    def test_all_nodes_must_observe_the_complete_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for index in range(4):
                log_dir = parent / f"node{index}" / "log"
                log_dir.mkdir(parents=True)
                (log_dir / "log_test.log").write_text(
                    "notifyGroupNodeInfo,connectedNodeSize=4\n", encoding="utf-8"
                )

            self.assertEqual(
                readiness.wait_for_convergence(parent, 4, 0), [4, 4, 4, 4]
            )

    def test_timeout_reports_each_nodes_observed_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for index, count in enumerate((4, 3, 2, 1)):
                log_dir = parent / f"node{index}" / "log"
                log_dir.mkdir(parents=True)
                (log_dir / "log_test.log").write_text(
                    f"notifyGroupNodeInfo,connectedNodeSize={count}\n",
                    encoding="utf-8",
                )

            with self.assertRaisesRegex(
                TimeoutError, "node0=4, node1=3, node2=2, node3=1"
            ):
                readiness.wait_for_convergence(parent, 4, 0)


if __name__ == "__main__":
    unittest.main()
