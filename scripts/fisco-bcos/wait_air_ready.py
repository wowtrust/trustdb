#!/usr/bin/env python3
"""Wait until every Air node observes the complete group membership."""

from __future__ import annotations

import argparse
import re
import time
from pathlib import Path
from typing import Callable


CONNECTED_NODES_RE = re.compile(r"notifyGroupNodeInfo,connectedNodeSize=(\d+)")


def observed_connected_nodes(node_dir: Path) -> int:
    observed = 0
    for log_path in sorted((node_dir / "log").glob("log_*.log")):
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        observed = max(
            observed,
            *(int(match) for match in CONNECTED_NODES_RE.findall(text)),
        )
    return observed


def wait_for_convergence(
    node_parent: Path,
    node_count: int,
    timeout_seconds: float,
    poll_seconds: float = 0.25,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> list[int]:
    deadline = monotonic() + timeout_seconds
    while True:
        observed = [
            observed_connected_nodes(node_parent / f"node{index}")
            for index in range(node_count)
        ]
        if all(value >= node_count for value in observed):
            return observed
        if monotonic() >= deadline:
            details = ", ".join(
                f"node{index}={value}" for index, value in enumerate(observed)
            )
            raise TimeoutError(
                f"four-node group did not converge within {timeout_seconds:g}s: {details}"
            )
        sleep(poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-parent", required=True, type=Path)
    parser.add_argument("--node-count", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=30)
    args = parser.parse_args()
    try:
        wait_for_convergence(
            args.node_parent,
            args.node_count,
            args.timeout_seconds,
        )
    except TimeoutError as exc:
        parser.exit(1, f"Air readiness check failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
