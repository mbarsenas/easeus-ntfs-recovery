import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fixtures.generate_deleted_vhdx_fixture import generate_fixture
from src.ntfs_recovery import NTFSVolume, VHDXReader, validate_ntfs_candidate


class DeletedVHDXFixtureTests(unittest.TestCase):
    def test_deleted_nonresident_discovery_and_recovery(self):
        with tempfile.TemporaryDirectory() as source_dir:
            image = Path(source_dir) / "deleted-fixture.vhdx"
            manifest_path = Path(source_dir) / "deleted-fixture.json"
            generate_fixture(image, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected = next(item for item in manifest["files"] if item["record"] == 16)

            with VHDXReader(image) as reader:
                candidate = validate_ntfs_candidate(reader, 0)
                self.assertEqual(candidate.offset, 0)
                self.assertEqual(candidate.length_bytes, manifest["geometry"]["total_sectors"] * 512)
                self.assertTrue(candidate.mft_record_readable)
                with NTFSVolume(reader) as volume:
                    discovered = list(volume.discover_deleted_files())
                    record16 = next(item for item in discovered if item.record.number == 16)
                    self.assertFalse(record16.record.in_use)
                    self.assertEqual(record16.record.sequence, 2)
                    self.assertEqual(record16.allocation.status, "unallocated")
                    self.assertEqual(
                        [(run.lcn, run.length, run.vcn) for run in record16.data.runs],
                        [(340, 1, 0), (345, 1, 1)],
                    )
                    self.assertNotIn("project-notes.txt", [item.record.names[0].name for item in discovered])
                    self.assertNotIn("fragmented-test.bin", [item.record.names[0].name for item in discovered])

                    with tempfile.TemporaryDirectory(dir="/dev/shm") as destination:
                        results = volume.recover_selected(
                            destination, records=[16], include_deleted=True
                        )
                        self.assertEqual(results[0]["status"], "recovered")
                        self.assertEqual(results[0]["allocation_status"], "unallocated")
                        self.assertFalse(results[0]["override_used"])
                        outputs = [path for path in Path(destination).rglob("*")
                                   if path.is_file() and path.name != "recovery-log.jsonl"]
                        self.assertEqual(len(outputs), 1)
                        self.assertEqual(outputs[0].stat().st_size, expected["size"])
                        self.assertEqual(
                            hashlib.sha256(outputs[0].read_bytes()).hexdigest(),
                            expected["sha256"],
                        )


if __name__ == "__main__":
    unittest.main()
