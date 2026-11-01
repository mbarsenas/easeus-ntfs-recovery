import json
import tempfile
import unittest
from pathlib import Path

from fixtures.run_ntfs_benchmark import run_benchmark


class NTFSBenchmarkTests(unittest.TestCase):
    def test_benchmark_report_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "benchmark.json"
            result = run_benchmark(report)
            self.assertTrue(result["pass"])
            self.assertTrue(result["image"]["sha256"])
            self.assertEqual(result["candidate"]["count"], 1)
            self.assertEqual(result["inventory"]["malformed_record_14_present"], False)
            self.assertTrue(result["allocation_safety"]["mixed_deleted_skipped"])
            self.assertTrue(result["allocation_safety"]["unallocated_deleted_recovered"])
            self.assertTrue(all(row["status_match"] for row in result["files"]))
            self.assertTrue(all(
                row["sha256_match"] is True
                for row in result["files"]
                if row["expected_status"] == "recovered"
            ))
            self.assertIsNone(next(row["sha256_match"] for row in result["files"] if row["record"] == 13))
            self.assertEqual(json.loads(report.read_text(encoding="utf-8")), result)


if __name__ == "__main__":
    unittest.main()
