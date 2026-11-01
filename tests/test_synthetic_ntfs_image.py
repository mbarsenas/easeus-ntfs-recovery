import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fixtures.generate_ntfs_test_image import build_image, generate_image
from src.ntfs_recovery import NTFSVolume


class SyntheticNTFSImageTests(unittest.TestCase):
    def test_generated_image_is_reproducible_and_consumable(self):
        image_a, manifest_a = build_image()
        image_b, manifest_b = build_image()
        self.assertEqual(image_a, image_b)
        self.assertEqual(manifest_a, manifest_b)

        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "fixture.img"
            manifest_path = Path(tmp) / "fixture.json"
            generated = generate_image(image_path, manifest_path)
            self.assertEqual(hashlib.sha256(image_a).hexdigest(), generated["image_sha256"])
            self.assertEqual(generated, json.loads(manifest_path.read_text(encoding="utf-8")))

            with NTFSVolume(image_path) as volume:
                rows = {row["record"]: row for row in volume.inventory(include_deleted=True)}
                self.assertEqual(rows[9]["path"], r"\Documents\Reports\fragmented.bin")
                self.assertEqual(rows[12]["allocation_status"], "unallocated")
                self.assertEqual(rows[13]["allocation_status"], "mixed")
                self.assertNotIn(14, rows)

                expected = {item["record"]: item for item in generated["files"]}
                for record in (9, 10, 11, 12):
                    data = volume.recover(volume.read_record(record))
                    self.assertEqual(hashlib.sha256(data).hexdigest(), expected[record]["sha256"])

                with self.assertRaises(ValueError):
                    volume.recover(volume.read_record(13))
                with self.assertRaises(ValueError):
                    volume.recover(volume.read_record(15))

    def test_deleted_discovery_is_independent_of_directory_indexes(self):
        with tempfile.TemporaryDirectory() as tmp:
            image_path = Path(tmp) / "fixture.img"
            manifest_path = Path(tmp) / "fixture.json"
            generate_image(image_path, manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected = {item["record"]: item for item in manifest["files"]}

            with NTFSVolume(image_path) as volume:
                discovered = list(volume.discover_deleted_files())
                by_record = {item.record.number: item for item in discovered}
                self.assertEqual(set(by_record), {12, 13})
                self.assertEqual(by_record[12].allocation.status, "unallocated")
                self.assertEqual(by_record[13].allocation.status, "mixed")
                self.assertEqual(
                    [(run.lcn, run.length, run.vcn) for run in by_record[12].data.runs],
                    [(320, 1, 0)],
                )
                self.assertEqual(
                    [(run.lcn, run.length, run.vcn) for run in by_record[13].data.runs],
                    [(321, 1, 0), (322, 1, 1)],
                )

                with tempfile.TemporaryDirectory(dir="/dev/shm") as destination:
                    result = volume.recover_selected(
                        destination, records=[12, 13], include_deleted=True
                    )
                    statuses = {row["source_record"]: row for row in result}
                    self.assertEqual(statuses[12]["status"], "recovered")
                    self.assertEqual(statuses[13]["status"], "skipped-allocation")
                    output = next(Path(destination).rglob("deleted-free.txt"))
                    self.assertEqual(output.stat().st_size, expected[12]["size"])
                    self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),
                                     expected[12]["sha256"])


if __name__ == "__main__":
    unittest.main()
