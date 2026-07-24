import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import performance


class PerformanceStatsTests(unittest.TestCase):
    def test_summarize_uses_nearest_rank_without_mutating_input(self):
        values = list(range(20, 0, -1))
        original = values.copy()

        result = performance.summarize_ns(values)

        self.assertEqual(values, original)
        self.assertEqual(
            result,
            {"unit": "ns", "n": 20, "p50_ns": 10, "p95_ns": 19, "max_ns": 20},
        )

    def test_summarize_rejects_empty_negative_and_boolean_samples(self):
        for values in ([], [1, -1], [1, True]):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    performance.summarize_ns(values)

    def test_build_performance_block_aggregates_all_required_stages(self):
        client_sample = {
            "prepare_sign_encode_ns": 1,
            "submit_to_receipt_ns": 2,
            "receipt_proof_retrieval_ns": 3,
            "transaction_proof_retrieval_ns": 4,
            "block_retrieval_ns": 5,
        }
        verification_sample = {
            "receipt_verification_ns": 6,
            "block_verification_ns": 7,
            "pbft_verification_ns": 8,
        }
        client = {
            "mode": "guomi",
            "performance": {
                "warmup_count": 3,
                "sample_count": 20,
                "payload": "fixed anchor(bytes32) call with one 32-byte digest",
                "deployment_excluded": True,
                "timing_samples": [copy.deepcopy(client_sample) for _ in range(20)],
            }
        }
        verification = {
            "performance": {
                "warmup_count": 3,
                "sample_count": 20,
                "samples": [copy.deepcopy(verification_sample) for _ in range(20)],
            }
        }

        result = performance.build_performance_block(client, verification)

        self.assertEqual(result["n"], 20)
        self.assertEqual(result["warmup_n"], 3)
        self.assertTrue(result["methodology"]["deployment_excluded"])
        self.assertEqual(
            set(result["stages"]),
            set(performance.CLIENT_STAGES) | set(performance.VERIFICATION_STAGES),
        )
        self.assertEqual(result["stages"]["local_pbft_verification"]["p95_ns"], 8)

    def test_build_rejects_mismatched_sample_counts(self):
        client = {
            "performance": {
                "warmup_count": 3,
                "sample_count": 20,
                "timing_samples": [{} for _ in range(19)],
            }
        }
        verification = {
            "performance": {
                "warmup_count": 3,
                "sample_count": 20,
                "samples": [{} for _ in range(20)],
            }
        }

        with self.assertRaisesRegex(ValueError, "sample counts"):
            performance.build_performance_block(client, verification)

    def test_build_rejects_deployment_samples(self):
        timing = {
            "prepare_sign_encode_ns": 1,
            "submit_to_receipt_ns": 2,
            "receipt_proof_retrieval_ns": 3,
            "transaction_proof_retrieval_ns": 4,
            "block_retrieval_ns": 5,
        }
        verification_timing = {
            "receipt_verification_ns": 6,
            "block_verification_ns": 7,
            "pbft_verification_ns": 8,
        }
        client = {
            "performance": {
                "warmup_count": 3,
                "sample_count": 20,
                "deployment_excluded": False,
                "timing_samples": [timing for _ in range(20)],
            }
        }
        verification = {
            "performance": {
                "warmup_count": 3,
                "sample_count": 20,
                "samples": [verification_timing for _ in range(20)],
            }
        }

        with self.assertRaisesRegex(ValueError, "deployment"):
            performance.build_performance_block(client, verification)


if __name__ == "__main__":
    unittest.main()
