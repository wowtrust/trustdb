#!/usr/bin/env python3
"""Build the comparable post-warmup FISCO BCOS performance evidence block."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


CLIENT_STAGES = {
    "prepare_sign_encode": "prepare_sign_encode_ns",
    "submit_to_receipt": "submit_to_receipt_ns",
    "receipt_proof_retrieval": "receipt_proof_retrieval_ns",
    "transaction_proof_retrieval": "transaction_proof_retrieval_ns",
    "block_retrieval": "block_retrieval_ns",
}
VERIFICATION_STAGES = {
    "local_receipt_verification": "receipt_verification_ns",
    "local_block_verification": "block_verification_ns",
    "local_pbft_verification": "pbft_verification_ns",
}


def summarize_ns(values: list[int]) -> dict[str, int | str]:
    if not values:
        raise ValueError("cannot summarize an empty sample set")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
        raise ValueError("duration samples must be non-negative integer nanoseconds")
    ordered = sorted(values)

    def nearest_rank(percentile: float) -> int:
        rank = max(1, math.ceil(percentile * len(ordered)))
        return ordered[rank - 1]

    return {
        "unit": "ns",
        "n": len(ordered),
        "p50_ns": nearest_rank(0.50),
        "p95_ns": nearest_rank(0.95),
        "max_ns": ordered[-1],
    }


def _summarize_stages(
    samples: list[dict[str, Any]],
    fields: dict[str, str],
) -> dict[str, dict[str, int | str]]:
    if not samples:
        raise ValueError("performance samples are missing")
    result = {}
    for stage, field in fields.items():
        try:
            values = [sample[field] for sample in samples]
        except (KeyError, TypeError) as error:
            raise ValueError(f"performance samples lack {field}") from error
        result[stage] = summarize_ns(values)
    return result


def build_performance_block(
    client: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    try:
        client_performance = client["performance"]
        verification_performance = verification["performance"]
        warmup_count = client_performance["warmup_count"]
        sample_count = client_performance["sample_count"]
        timing_samples = client_performance["timing_samples"]
        verification_samples = verification_performance["samples"]
    except (KeyError, TypeError) as error:
        raise ValueError("performance evidence is incomplete") from error

    if (
        not isinstance(warmup_count, int)
        or isinstance(warmup_count, bool)
        or not 3 <= warmup_count <= 20
        or not isinstance(sample_count, int)
        or isinstance(sample_count, bool)
        or not 20 <= sample_count <= 100
    ):
        raise ValueError("performance sample bounds are invalid")
    if (
        len(timing_samples) != sample_count
        or len(verification_samples) != sample_count
        or verification_performance.get("warmup_count") != warmup_count
        or verification_performance.get("sample_count") != sample_count
    ):
        raise ValueError("client and local verification sample counts differ")
    if client_performance.get("deployment_excluded") is not True:
        raise ValueError("contract deployment must be excluded from performance samples")
    mode = client.get("mode")
    if mode not in ("standard", "guomi"):
        raise ValueError("performance evidence has an unsupported crypto mode")

    stages = _summarize_stages(timing_samples, CLIENT_STAGES)
    stages.update(_summarize_stages(verification_samples, VERIFICATION_STAGES))
    if any(stage["n"] != sample_count for stage in stages.values()):
        raise ValueError("a stage summary has the wrong sample count")

    return {
        "schema_version": 1,
        "mode": mode,
        "n": sample_count,
        "warmup_n": warmup_count,
        "methodology": {
            "comparison": "sequential_standard_vs_guomi_on_the_same_host_profile",
            "sample_order": "post_warmup_sequential",
            "percentile_method": "nearest_rank",
            "deployment_excluded": True,
            "payload": client_performance.get("payload", ""),
            "raw_samples_retained": True,
        },
        "stages": stages,
        "raw_samples": {
            "network": timing_samples,
            "local_verification": verification_samples,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True, help="smoke-client evidence JSON")
    parser.add_argument("--verification", required=True, help="local verification evidence JSON")
    args = parser.parse_args()
    client = json.loads(Path(args.client).read_text(encoding="utf-8"))
    verification = json.loads(Path(args.verification).read_text(encoding="utf-8"))
    print(json.dumps(build_performance_block(client, verification), sort_keys=True))


if __name__ == "__main__":
    main()
