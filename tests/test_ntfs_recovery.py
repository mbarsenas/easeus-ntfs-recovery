import io
import hashlib
import json
import os
import struct
import unittest
import dataclasses
import tempfile
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stderr

from src.ntfs_recovery import (
    Attribute,
    DataRun,
    DirectoryIndexEvidence,
    DeletedFileDiscovery,
    MFTRegionAnalyzer,
    MFTRegionCandidate,
    MFTRegionObservation,
    NTFSCandidateReconciler,
    NTFSCandidate,
    NTFSVolume,
    FileRecord,
    RawFileObservation,
    VolumeGeometry,
    apply_fixup,
    analyze_mft_regions,
    decode_data_runs,
    derive_backup_ntfs_candidate,
    easeus_candidates_duplicate,
    is_easeus_ntfs_boot_sector,
    iter_raw_file_records,
    parse_attributes,
    parse_file_record,
    parse_file_name,
    parse_index_entries,
    update_zero_length_candidate_extents,
    validate_ntfs_candidate,
    preview_recovery,
    create_recovery_manifest,
    load_recovery_manifest,
    recover_from_manifest,
    write_recovery_manifest,
    _SecureDestination,
    main,
)


class NTFSRecoveryTests(unittest.TestCase):
    @staticmethod
    def _allocation_volume(bitmap=None, total_clusters=16, bitmap_error=None):
        volume = object.__new__(NTFSVolume)
        volume.geometry = VolumeGeometry(512, 1, total_clusters, 1, 2, -10, -9)
        volume.offset = 0
        volume.f = io.BytesIO()
        volume._owned = False
        volume._mft_runs = None
        volume._bitmap_cache = bitmap
        volume._bitmap_error = bitmap_error
        return volume

    @staticmethod
    def _data_record(number, flags, runs):
        attr = Attribute(0x80, "", 0, 1, False, runs=runs,
                         data_size=sum(run.length for run in runs) * 512,
                         initialized_size=sum(run.length for run in runs) * 512,
                         lowest_vcn=runs[0].vcn if runs else 0,
                         highest_vcn=(runs[-1].vcn + runs[-1].length - 1) if runs else 0)
        return FileRecord(number, b"", 1, flags, [attr], [])
    @staticmethod
    def _raw_file_record(name="$MFT", sequence=7):
        record = bytearray(1024)
        record[:4] = b"FILE"
        struct.pack_into("<HH", record, 4, 0x30, 3)
        struct.pack_into("<H", record, 0x10, sequence)
        struct.pack_into("<H", record, 0x16, 1)
        struct.pack_into("<I", record, 0x1c, 1024)
        struct.pack_into("<H", record, 0x14, 0x38)

        value = bytearray(0x42 + len(name.encode("utf-16le")))
        struct.pack_into("<Q", value, 0, 5)
        value[0x40] = len(name)
        value[0x41] = 1
        value[0x42:] = name.encode("utf-16le")
        attr_length = (0x18 + len(value) + 7) & ~7
        struct.pack_into("<I", record, 0x38, 0x30)
        struct.pack_into("<I", record, 0x3c, attr_length)
        struct.pack_into("<I", record, 0x38 + 0x10, len(value))
        struct.pack_into("<H", record, 0x38 + 0x14, 0x18)
        record[0x38 + 0x18:0x38 + 0x18 + len(value)] = value
        struct.pack_into("<I", record, 0x38 + attr_length, 0xffffffff)

        struct.pack_into("<H", record, 0x30, 0xaabb)
        struct.pack_into("<HH", record, 0x32, 0x1111, 0x2222)
        record[510:512] = record[1022:1024] = b"\xbb\xaa"
        return record

    @staticmethod
    def _candidate_boot(total=20):
        b = bytearray(512)
        b[3:11] = b"NTFS    "
        struct.pack_into("<HB", b, 0x0b, 512, 8)
        struct.pack_into("<QQQ", b, 0x28, total, 1, 2)
        struct.pack_into("<Q", b, 0x48, 2)
        struct.pack_into("<b", b, 0x40, -10)
        struct.pack_into("<b", b, 0x44, 1)
        b[0x1fe:0x200] = b"\x55\xaa"
        return b

    def test_easeus_dbr_predicate_rules(self):
        b = self._candidate_boot()
        b[0x15] = 0xF8  # EaseUS does not test this media byte.
        self.assertTrue(is_easeus_ntfs_boot_sector(bytes(b)))
        b[0x16] = 1
        self.assertFalse(is_easeus_ntfs_boot_sector(bytes(b)))

        b = self._candidate_boot()
        struct.pack_into("<H", b, 0x0b, 1536)
        self.assertTrue(is_easeus_ntfs_boot_sector(bytes(b)))
        with self.assertRaises(ValueError):
            VolumeGeometry.from_boot_sector(bytes(b))  # retained safety restriction

    def test_read_record_preserves_intra_cluster_and_fragmented_mft_offsets(self):
        # 512-byte clusters and 1024-byte FILE records force every record to
        # cross a cluster boundary. The logical MFT stream is split into two
        # physical extents while preserving record order.
        volume = object.__new__(NTFSVolume)
        volume.geometry = VolumeGeometry(512, 1, 32, 1, 2, -10, -10)
        volume.offset = 0
        volume._owned = False
        volume._mft_runs = [DataRun(1, 4, 0), DataRun(5, 4, 4)]
        volume._bitmap_cache = None
        volume._bitmap_error = None
        image = bytearray(10 * 512)
        logical = b"".join(bytes(self._raw_file_record(name=f"file-{n}")) for n in range(4))
        for logical_cluster, physical_cluster in enumerate((1, 2, 3, 4, 5, 6, 7, 8)):
            start = logical_cluster * 512
            image[physical_cluster * 512:(physical_cluster + 1) * 512] = logical[start:start + 512]
        volume.f = io.BytesIO(image)
        for number in range(4):
            record = volume.read_record(number, expand_attributes=False)
            self.assertEqual(record.number, number)
            self.assertEqual(record.names[0].name, f"file-{number}")
        with self.assertRaises(ValueError):
            volume.read_record(-1)
        with self.assertRaises(ValueError):
            volume.read_record(4)

    def test_read_record_short_mft_extent_fails_safely(self):
        volume = object.__new__(NTFSVolume)
        volume.geometry = VolumeGeometry(512, 1, 8, 1, 2, -10, -10)
        volume.offset = 0
        volume._owned = False
        volume._mft_runs = [DataRun(1, 1, 0)]
        volume._bitmap_cache = None
        volume._bitmap_error = None
        volume.f = io.BytesIO(bytearray(2 * 512))
        with self.assertRaises(ValueError):
            volume.read_record(1)

    def test_easeus_extent_clamping_and_eight_sector_minimum(self):
        b = self._candidate_boot(total=20)
        image = bytearray(14 * 512)
        image[512:1024] = b
        candidate = validate_ntfs_candidate(io.BytesIO(image), 512)
        self.assertEqual(candidate.length_bytes, 13 * 512)
        self.assertEqual(candidate.source_kind, "primary")
        self.assertEqual(candidate.easeus_duplicate_key, (13 * 512, 2))

        short = bytearray(8 * 512)
        short[512:1024] = b
        with self.assertRaises(ValueError):
            validate_ntfs_candidate(io.BytesIO(short), 512)

    def test_easeus_backup_start_and_duplicate_extent_update(self):
        b = self._candidate_boot(total=20)
        image = bytearray(40 * 512)
        image[30 * 512:31 * 512] = b
        backup = derive_backup_ntfs_candidate(io.BytesIO(image), 30)
        self.assertEqual(backup.offset, 10 * 512)
        self.assertEqual(backup.backup_offset, 30 * 512)
        self.assertEqual(backup.source_kind, "backup")
        self.assertEqual(backup.mode, 2)

        geometry = VolumeGeometry.from_boot_sector(bytes(b))
        empty = NTFSCandidate(0, geometry, bytes(b), length_bytes=0, mftmirr_lcn=2)
        self.assertEqual(update_zero_length_candidate_extents([empty], backup), 1)
        self.assertEqual(empty.length_bytes, backup.length_bytes)
        self.assertTrue(easeus_candidates_duplicate(empty, backup))

    def test_raw_file_discovery_is_bounded_and_identifies_special_names(self):
        record = self._raw_file_record("$MFT", sequence=9)
        image = bytearray(5 * 512 + len(record))
        image[2 * 512:2 * 512 + len(record)] = record
        self.assertEqual(list(iter_raw_file_records(io.BytesIO(image), 2, 1)), [])
        found = list(iter_raw_file_records(io.BytesIO(image), 2, 3))
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], RawFileObservation)
        self.assertEqual(found[0].offset, 2 * 512)
        self.assertEqual(found[0].sector, 2)
        self.assertIsNone(found[0].record_number)
        self.assertEqual(found[0].sequence, 9)
        self.assertEqual(found[0].special_name, "$MFT")
        self.assertEqual(found[0].validation_status, "validated")

    def test_raw_file_discovery_skips_invalid_records(self):
        bad = self._raw_file_record("$Bitmap")
        bad[510:512] = b"\x00\x00"
        good = self._raw_file_record("ordinary", sequence=4)
        image = bytearray(8 * 512)
        image[0:1024] = bad
        image[3 * 512:3 * 512 + 1024] = good
        found = list(iter_raw_file_records(io.BytesIO(image), 0, 8))
        self.assertEqual([(item.sector, item.special_name) for item in found], [(3, None)])

    def test_raw_file_discovery_is_incremental_and_deduplicated(self):
        record = self._raw_file_record("$MFTMirr")
        image = bytearray(64 * 512)
        image[512:512 + len(record)] = record
        iterator = iter_raw_file_records(io.BytesIO(image), 0, 64, chunk_sectors=1)
        first = next(iterator)
        self.assertEqual(first.special_name, "$MFTMirr")
        self.assertEqual(list(iterator), [])

    @staticmethod
    def _region_observation(offset, record_size=1024, name="ordinary", sequence=1):
        raw = NTFSRecoveryTests._raw_file_record(name, sequence=sequence)
        record = parse_file_record(bytes(raw), -1, 512)
        return RawFileObservation(
            offset=offset, sector=offset // 512, record_number=None,
            sequence=record.sequence, flags=record.flags, record_size=record_size,
            names=tuple(record.names), special_name=name if name in {"$MFT", "$MFTMirr", "$Bitmap"} else None,
            validation_status="validated", record=record,
        )

    def test_mft_region_analysis_requires_coherent_repetition(self):
        observations = [self._region_observation(0x10000 + n * 1024, name="$MFT" if n == 0 else "ordinary")
                        for n in range(3)]
        result = analyze_mft_regions(observations)
        self.assertEqual(len(result.regions), 1)
        self.assertEqual(result.regions[0].layout, "contiguous")
        self.assertEqual(len(result.regions[0].observations), 3)
        self.assertFalse(result.regions[0].validation_state == "validated")
        self.assertIsNone(result.regions[0].observations[0].record_number)

    def test_mft_region_analysis_keeps_isolated_observations(self):
        result = analyze_mft_regions([self._region_observation(0x20000, name="$MFT")])
        self.assertEqual(result.regions, ())
        self.assertEqual(len(result.isolated), 1)

    def test_mft_region_analysis_reports_conflicting_sizes(self):
        first = self._region_observation(0x30000)
        conflicting = dataclasses.replace(first, record_size=2048)
        result = analyze_mft_regions([first, conflicting])
        self.assertEqual(len(result.conflicts), 1)
        self.assertEqual(result.record_size_hypotheses, (1024,))
        self.assertEqual(result.regions, ())

    def test_mft_region_analysis_deduplicates_and_marks_fragments(self):
        first = self._region_observation(0x40000)
        duplicate = dataclasses.replace(first)
        later = self._region_observation(0x42000)
        analyzer = MFTRegionAnalyzer()
        analyzer.consume_all([first, duplicate, later])
        result = analyzer.finish()
        self.assertEqual(result.duplicates, 1)
        self.assertEqual(len(result.regions), 1)
        self.assertEqual(result.regions[0].layout, "fragmented")
        self.assertEqual(result.regions[0].gaps, (0x2000,))

    @staticmethod
    def _reconciliation_candidate(offset=0x10000):
        boot = NTFSRecoveryTests._candidate_boot()
        geometry = VolumeGeometry.from_boot_sector(bytes(boot))
        return NTFSCandidate(offset, geometry, bytes(boot), length_bytes=0x100000,
                             mftmirr_lcn=2, source_kind="primary", mode=1)

    @staticmethod
    def _mft_region(start, record_size=1024):
        observations = tuple(
            MFTRegionObservation(start + n * record_size, start // 512 + n, None,
                                 n + 1, 1, record_size, ("$MFT",) if n == 0 else (),
                                 "$MFT" if n == 0 else None, "validated")
            for n in range(2)
        )
        return MFTRegionCandidate(
            record_size=record_size, start_offset=start,
            end_offset=start + 2 * record_size, observations=observations,
            layout="contiguous", contiguous_runs=1, gaps=(),
            system_name_clues=("$MFT",),
            evidence=("two validated FILE observations",), contradictions=(),
        )

    def test_candidate_reconciliation_matches_geometry_and_explicit_index_identity(self):
        candidate = self._reconciliation_candidate()
        mft_start = candidate.offset + candidate.geometry.mft_lcn * candidate.geometry.cluster_size
        reconciler = NTFSCandidateReconciler()
        reconciler.add_candidate(candidate)
        reconciler.add_mft_region(self._mft_region(mft_start))
        reconciler.add_directory_evidence(DirectoryIndexEvidence(
            source_offset=mft_start, index_kind="$I30", volume_offset=candidate.offset
        ))
        result = reconciler.finalize()
        report = result.candidates[0]
        self.assertEqual(report.validation_status, "DBR-candidate-unresolved")
        self.assertEqual(report.associated_region_start, mft_start)
        self.assertEqual(report.associated_directory_evidence, 1)
        self.assertIn("MFT-region record size matches DBR geometry", report.supporting_evidence)
        self.assertEqual(result.unassociated_region_starts, ())

    def test_candidate_reconciliation_reports_conflicting_region_geometry(self):
        candidate = self._reconciliation_candidate()
        mft_start = candidate.offset + candidate.geometry.mft_lcn * candidate.geometry.cluster_size
        reconciler = NTFSCandidateReconciler()
        reconciler.add_candidate(candidate)
        reconciler.add_mft_region(self._mft_region(mft_start, record_size=2048))
        report = reconciler.finalize().candidates[0]
        self.assertEqual(report.validation_status, "contradictory-evidence")
        self.assertTrue(report.contradictory_evidence)

    def test_candidate_reconciliation_keeps_unassociated_evidence_separate(self):
        candidate = self._reconciliation_candidate()
        reconciler = NTFSCandidateReconciler()
        reconciler.add_candidate(candidate)
        reconciler.add_mft_region(self._mft_region(0x900000))
        raw = self._raw_file_record("$Bitmap")
        record = parse_file_record(bytes(raw), -1, 512)
        reconciler.add_raw_observation(RawFileObservation(
            offset=0x900000, sector=0x900000 // 512, record_number=None,
            sequence=record.sequence, flags=record.flags, record_size=1024,
            names=tuple(record.names), special_name="$Bitmap",
            validation_status="validated", record=record,
        ))
        reconciler.add_directory_evidence(DirectoryIndexEvidence(
            source_offset=0x900000, index_kind="$I30"
        ))
        result = reconciler.finalize()
        self.assertEqual(result.unassociated_region_starts, (0x900000,))
        self.assertEqual(result.unassociated_raw_offsets, (0x900000,))
        self.assertEqual(len(result.unassociated_directory_evidence), 1)
        self.assertIsNone(result.candidates[0].associated_region_start)

    def test_mapping_pairs_signed_relative_and_sparse(self):
        # 3 clusters at LCN 100, 2 sparse, 1 at LCN 95 (delta -5).
        self.assertEqual(decode_data_runs(bytes.fromhex("11 03 64 01 02 11 01 fb 00")),
                         [DataRun(100, 3, 0), DataRun(None, 2, 3), DataRun(95, 1, 5)])

    def test_attribute_list_extension_record_is_chained_for_recovery(self):
        entry = bytearray(0x20)
        struct.pack_into("<IH", entry, 0, 0x80, 0x20)
        struct.pack_into("<Q", entry, 8, 1)  # lowest VCN
        struct.pack_into("<Q", entry, 0x10, 101 | (7 << 48))
        struct.pack_into("<H", entry, 0x18, 2)
        base_data = Attribute(0x80, "", 0, 1, False, runs=[DataRun(10, 1, 0)],
                              data_size=1024, initialized_size=1024,
                              lowest_vcn=0, highest_vcn=0)
        extension_data = Attribute(0x80, "", 0, 2, False, runs=[DataRun(12, 1, 1)],
                                    data_size=1024, initialized_size=1024,
                                    lowest_vcn=1, highest_vcn=1)
        main = FileRecord(100, b"", 3, 1, [
            Attribute(0x20, "", 0, 9, True, value=bytes(entry)), base_data
        ], [])
        extension = FileRecord(101, b"", 7, 1, [extension_data], [])

        class ExtensionVolume(NTFSVolume):
            def __init__(self):
                self._records = {100: main, 101: extension}
                self.geometry = VolumeGeometry(512, 1, 32, 1, 2, -10, -9)
                self.offset = 0
                self.f = io.BytesIO(b"\0" * (16 * 512))
                self.f.seek(10 * 512); self.f.write(b"A" * 512)
                self.f.seek(12 * 512); self.f.write(b"B" * 512)
                self._owned = False
                self._mft_runs = None
                self._bitmap_cache = None
                self._bitmap_error = None

            def read_record(self, number, expand_attributes=True):
                record = self._records[number]
                return self.expand_attributes(record) if expand_attributes else record

        volume = ExtensionVolume()
        expanded = volume.read_record(100)
        self.assertEqual(len([a for a in expanded.attrs if a.type == 0x80]), 2)
        self.assertEqual(volume.recover(expanded), b"A" * 512 + b"B" * 512)

    def test_missing_and_stale_parent_references_have_deterministic_paths(self):
        def resident_file(number, name, parent, parent_sequence=0, sequence=1):
            value = bytearray(0x42 + len(name.encode("utf-16le")))
            struct.pack_into("<Q", value, 0, parent | (parent_sequence << 48))
            value[0x40] = len(name); value[0x41] = 1
            value[0x42:] = name.encode("utf-16le")
            return FileRecord(number, b"", sequence, 1,
                              [Attribute(0x30, "", 0, 1, True, value=bytes(value)),
                               Attribute(0x80, "", 0, 2, True, value=b"x")],
                              [parse_file_name(bytes(value))])

        records = [
            resident_file(6, "Parent", 5, parent_sequence=1, sequence=4),
            resident_file(7, "Child.bin", 6, parent_sequence=4),
            resident_file(8, "Orphan.bin", 999, parent_sequence=1),
            resident_file(9, "Stale.bin", 6, parent_sequence=99),
        ]
        volume = object.__new__(NTFSVolume)
        volume.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
        volume.offset = 0; volume.f = io.BytesIO(); volume._owned = False
        volume._mft_runs = None; volume._bitmap_cache = None; volume._bitmap_error = "not needed"
        volume.iter_mft = lambda include_deleted=True, limit=None: iter(records)
        with tempfile.TemporaryDirectory() as temp:
            results = volume.recover_selected(temp, records=[7, 8, 9], include_deleted=False)
            self.assertEqual({r["source_record"]: r["status"] for r in results},
                             {7: "recovered", 8: "recovered", 9: "recovered"})
            self.assertEqual((Path(temp) / "Parent" / "Child.bin").read_bytes(), b"x")
            self.assertEqual((Path(temp) / "Orphan.bin").read_bytes(), b"x")
            self.assertEqual((Path(temp) / "Parent" / "Stale.bin").read_bytes(), b"x")

    def test_mixed_reused_clusters_skip_by_default_and_override_exact_bytes(self):
        record = self._data_record(30, 0, [DataRun(1, 1, 0), DataRun(9, 1, 1)])
        volume = self._allocation_volume(bytes([0x02, 0x00]))
        volume.f = io.BytesIO(b"\0" * (10 * 512))
        volume.f.seek(1 * 512); volume.f.write(b"R" * 512)
        volume.f.seek(9 * 512); volume.f.write(b"F" * 512)
        volume.iter_mft = lambda include_deleted=True, limit=None: iter([record])
        with tempfile.TemporaryDirectory() as temp:
            skipped = volume.recover_selected(temp)
            self.assertEqual(skipped[0]["allocation_status"], "mixed")
            self.assertEqual(skipped[0]["status"], "skipped-allocation")
            recovered = volume.recover_selected(temp, allow_deleted_uncertain=True)
            self.assertEqual(recovered[0]["status"], "recovered")
            self.assertEqual((Path(temp) / "record-30").read_bytes(), b"R" * 512 + b"F" * 512)

    def test_truncated_or_unreadable_bitmap_keeps_deleted_recovery_unknown(self):
        record = self._data_record(31, 0, [DataRun(1, 1, 0)])
        for bitmap, error in ((b"\0", None), (None, "bitmap read failed")):
            volume = self._allocation_volume(bitmap, total_clusters=16, bitmap_error=error)
            volume.iter_mft = lambda include_deleted=True, limit=None: iter([record])
            with tempfile.TemporaryDirectory() as temp:
                result = volume.recover_selected(temp)
                self.assertEqual(result[0]["allocation_status"], "unknown")
                self.assertEqual(result[0]["status"], "skipped-allocation")
                self.assertFalse((Path(temp) / "record-31").exists())

    def test_sparse_multiple_extents_and_initialized_size_boundaries(self):
        volume = self._allocation_volume(bytes(4), total_clusters=32)
        raw = bytearray(4 * 512)
        raw[512:1024] = b"A" * 512
        raw[3 * 512:4 * 512] = b"C" * 512
        volume.f = io.BytesIO(bytes(raw))
        full = Attribute(0x80, "", 0, 1, False,
                         runs=[DataRun(1, 1, 0), DataRun(None, 1, 1), DataRun(3, 1, 2)],
                         data_size=3 * 512, initialized_size=3 * 512,
                         lowest_vcn=0, highest_vcn=2)
        bounded = dataclasses.replace(full, initialized_size=2 * 512)
        self.assertEqual(b"".join(volume.iter_attribute_chunks(full)),
                         b"A" * 512 + b"\0" * 512 + b"C" * 512)
        self.assertEqual(volume.recover(FileRecord(32, b"", 1, 1, [bounded], [])),
                         b"A" * 512 + b"\0" * 1024)

    def test_read_only_preview_reports_candidates_selection_and_confidence(self):
        geometry = VolumeGeometry(512, 1, 32, 1, 2, -10, -9)
        accepted = NTFSCandidate(
            offset=0, geometry=geometry, boot_sector=b"boot", backup_matches=True,
            mft_record_readable=True, mft_runs_readable=True, length_bytes=16 * 512,
            notes=["backup DBR geometry matches", "$MFT record 0 and mapping pairs readable"],
        )
        rows = [
            {"record": 10, "path": "\\Parent", "name": "Parent", "parent": 5,
             "directory": True, "allocated": True, "recoverable": False,
             "metadata_recoverable": False, "content_status": "not-assessed",
             "allocation_status": "not-assessed", "allocation_warnings": [], "size": 0, "names": 1},
            {"record": 11, "path": "\\Parent\\active.bin", "name": "active.bin", "parent": 10,
             "directory": False, "allocated": True, "recoverable": True,
             "metadata_recoverable": True, "content_status": "not-assessed",
             "allocation_status": "not-assessed", "allocation_warnings": [], "size": 4, "names": 1},
            {"record": 12, "path": "\\deleted.bin", "name": "deleted.bin", "parent": 5,
             "directory": False, "allocated": False, "recoverable": True,
             "metadata_recoverable": True, "content_status": "not-assessed",
             "allocation_status": "mixed", "allocation_warnings": ["potential reuse"], "size": 8, "names": 1},
        ]

        class PreviewVolume:
            def __init__(self, source, offset=0): pass
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def inventory(self, include_deleted=True, limit=None): return rows

        with tempfile.NamedTemporaryFile() as source, tempfile.TemporaryDirectory() as destination:
            with patch("src.ntfs_recovery.validate_ntfs_candidate",
                       side_effect=[accepted, ValueError("bad DBR")]), \
                 patch("src.ntfs_recovery.NTFSVolume", PreviewVolume):
                report = preview_recovery(source.name, [0, 512], destination, records=[10])
        self.assertFalse(report["extraction_performed"])
        self.assertFalse(report["physical_scan_performed"])
        self.assertEqual([item["accepted"] for item in report["candidates"]], [True, False])
        files = {item["record"]: item for item in report["volumes"][0]["files"]}
        self.assertTrue(files[10]["selected"])
        self.assertTrue(files[11]["selected"])  # selected directory descendant
        self.assertFalse(files[12]["selected"])
        self.assertEqual(files[12]["content_confidence"], "potentially-reused")
        self.assertIn("backup DBR geometry matches", report["volumes"][0]["candidate"]["reasons"])
        with self.assertRaises(ValueError):
            preview_recovery(source.name, [0], source.name)

    def test_manifest_is_canonical_and_tamper_detected(self):
        row = {"record": 11, "path": "\\file.bin", "name": "file.bin", "parent": 5,
               "directory": False, "allocated": True, "recoverable": True,
               "metadata_recoverable": True, "content_status": "not-assessed",
               "allocation_status": "not-assessed", "allocation_warnings": [], "size": 4,
               "names": 1, "deleted": False, "metadata_confidence": "record-and-path",
               "content_confidence": "active-file-not-assessed", "selected": True}
        candidate = {"offset": 0, "accepted": True, "length_bytes": 16384,
                     "geometry": dataclasses.asdict(VolumeGeometry(512, 1, 32, 1, 2, -10, -9)),
                     "reasons": ["valid NTFS boot sector and supported geometry"]}
        preview = {"destination": "", "candidates": [candidate],
                   "volumes": [{"candidate": candidate,
                                "selection": {"requested_records": [11], "selected_records": [11]},
                                "files": [row]}]}
        with tempfile.NamedTemporaryFile() as source, tempfile.TemporaryDirectory() as destination:
            manifest_path = Path(destination) / "job.json"
            with patch("src.ntfs_recovery.preview_recovery", return_value={**preview, "destination": str(Path(destination).resolve())}):
                manifest = create_recovery_manifest(source.name, [0], destination, records=[11], output=manifest_path)
            loaded = load_recovery_manifest(manifest_path)
            self.assertEqual(loaded["manifest_sha256"], manifest["manifest_sha256"])
            tampered = dict(loaded); tampered["destination"] = str(Path(destination).resolve() / "changed")
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_recovery_manifest(manifest_path)

    def test_manifest_recovery_revalidates_and_hashes_output(self):
        geometry = VolumeGeometry(512, 1, 32, 1, 2, -10, -9)
        candidate = NTFSCandidate(0, geometry, b"boot", length_bytes=16384)
        row = {"record": 11, "path": "\\file.bin", "name": "file.bin", "parent": 5,
               "directory": False, "allocated": True, "recoverable": True,
               "metadata_recoverable": True, "content_status": "not-assessed",
               "allocation_status": "not-assessed", "allocation_warnings": [], "size": 4,
               "names": 1, "deleted": False, "metadata_confidence": "record-and-path",
               "content_confidence": "active-file-not-assessed", "selected": True}
        with tempfile.NamedTemporaryFile() as source, tempfile.TemporaryDirectory() as destination:
            destination_path = Path(destination) / "out"
            manifest = {
                "manifest_version": 1, "created_utc": "2026-01-01T00:00:00+00:00",
                "source": {"path": str(Path(source.name).resolve()), "size": 0,
                           "mtime_ns": Path(source.name).stat().st_mtime_ns,
                           "st_dev": Path(source.name).stat().st_dev,
                           "st_ino": Path(source.name).stat().st_ino},
                "destination": str(destination_path.resolve()), "candidate": {
                    "offset": 0, "length_bytes": 16384, "geometry": dataclasses.asdict(geometry)},
                "selected_files": [row], "selection": {}, "warnings": [],
                "extraction_performed": False, "physical_scan_performed": False,
            }
            manifest_path = Path(destination) / "job.json"
            write_recovery_manifest(manifest_path, manifest)

            class RecoveryVolume:
                def __init__(self, source, offset=0): pass
                def __enter__(self): return self
                def __exit__(self, *_): pass
                def inventory(self, include_deleted=True, limit=None): return [row]
                def recover_selected(self, destination, **kwargs):
                    target = Path(destination) / "file.bin"
                    Path(destination).mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"DATA")
                    return [{"status": "recovered", "source_record": 11, "size": 4,
                             "source_path": "\\file.bin", "destination": str(target),
                             "error": None, "allocation_status": "not-assessed",
                             "allocation_warnings": [], "override_used": False}]

            with patch("src.ntfs_recovery.validate_ntfs_candidate", return_value=candidate), \
                 patch("src.ntfs_recovery.NTFSVolume", RecoveryVolume):
                report = recover_from_manifest(source.name, manifest_path)
            self.assertEqual(report["files"][0]["bytes_written"], 4)
            self.assertEqual(report["files"][0]["sha256"],
                             "c97c29c7a71b392b437ee03fd17f09bb10b75e879466fc0eb757b2c4a78ac938")

    def test_secure_destination_rejects_symlinks_traversal_and_source_filesystem(self):
        if not os.path.isdir("/dev/shm") or os.stat("/dev/shm").st_dev == os.stat("/tmp").st_dev:
            self.skipTest("requires a distinct synthetic filesystem")
        with tempfile.NamedTemporaryFile(dir="/tmp") as source, tempfile.TemporaryDirectory(dir="/dev/shm") as root:
            source_stat = os.fstat(source.fileno())
            with self.assertRaises(ValueError):
                _SecureDestination(Path(source.name).parent, source_stat)
            real = Path(root) / "real"
            real.mkdir()
            link = Path(root) / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                _SecureDestination(link / "out", source_stat)
            secure = _SecureDestination(Path(root) / "out", source_stat)
            with self.assertRaises(ValueError):
                secure.create_file(["..", "escape"], set())
            first, handle = secure.create_file(["file.bin"], set())
            handle.write(b"one"); handle.close()
            second, handle = secure.create_file(["file.bin"], set())
            handle.write(b"two"); handle.close(); secure.close()
            self.assertEqual(first.read_bytes(), b"one")
            self.assertEqual(second.read_bytes(), b"two")

    def test_pinned_source_descriptor_survives_replacement_and_detects_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            source_path = Path(temp) / "source.bin"
            source_path.write_bytes(b"original")
            with source_path.open("rb") as pinned:
                before = os.fstat(pinned.fileno())
                with source_path.open("ab") as changed:
                    changed.write(b"!")
                after_mutation = os.fstat(pinned.fileno())
                self.assertNotEqual(after_mutation.st_size, before.st_size)
                replacement = Path(temp) / "replacement.bin"
                replacement.write_bytes(b"replacement")
                os.replace(replacement, source_path)
                after_replace = os.fstat(pinned.fileno())
                self.assertEqual((after_mutation.st_dev, after_mutation.st_ino, after_mutation.st_size),
                                 (after_replace.st_dev, after_replace.st_ino, after_mutation.st_size))
                self.assertEqual(pinned.read(), b"original!")

    def test_secure_destination_closes_on_success_and_exception(self):
        if not os.path.isdir("/dev/shm") or os.stat("/dev/shm").st_dev == os.stat("/tmp").st_dev:
            self.skipTest("requires a distinct synthetic filesystem")
        with tempfile.NamedTemporaryFile(dir="/tmp") as source, tempfile.TemporaryDirectory(dir="/dev/shm") as root:
            for should_raise in (False, True):
                secure = _SecureDestination(Path(root) / ("out-success" if not should_raise else "out-error"),
                                             os.fstat(source.fileno()))
                fd = secure.fd
                try:
                    with secure:
                        if should_raise:
                            raise RuntimeError("synthetic failure")
                except RuntimeError:
                    pass
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_secure_log_rejects_symlink_and_existing_collision(self):
        if not os.path.isdir("/dev/shm") or os.stat("/dev/shm").st_dev == os.stat("/tmp").st_dev:
            self.skipTest("requires a distinct synthetic filesystem")
        with tempfile.NamedTemporaryFile(dir="/tmp") as source, tempfile.TemporaryDirectory(dir="/dev/shm") as root:
            secure = _SecureDestination(Path(root) / "out", os.fstat(source.fileno()))
            path, handle = secure.open_exclusive(Path(root) / "out" / "recovery-log.jsonl")
            handle.write("{}\n"); handle.close()
            with self.assertRaises(FileExistsError):
                secure.open_exclusive(path)
            link = Path(root) / "link"
            link.symlink_to(Path(root) / "out", target_is_directory=True)
            with self.assertRaises(ValueError):
                secure.open_exclusive(link / "evil.log")
            secure.close()

    def test_failed_recovery_removes_partial_output(self):
        class FailingVolume(NTFSVolume):
            def __init__(self, record):
                self._records = [record]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0; self.f = io.BytesIO(); self._owned = False
                self._source_stat = None; self._mft_runs = None
                self._bitmap_cache = bytes(2); self._bitmap_error = None
            def iter_mft(self, include_deleted=True, limit=None): return iter(self._records)
            def iter_attribute_chunks(self, attr, chunk_size=1024 * 1024):
                yield b"partial"
                raise IOError("synthetic read failure")

        record = self._data_record(40, 1, [DataRun(1, 1, 0)])
        with tempfile.TemporaryDirectory() as destination:
            result = FailingVolume(record).recover_selected(destination)
            self.assertEqual(result[0]["status"], "error")
            self.assertFalse((Path(destination) / "record-40").exists())

    def test_cli_reports_security_error_without_traceback(self):
        with tempfile.NamedTemporaryFile() as source:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = main([source.name, "--preview", "--destination", source.name])
            self.assertEqual(status, 2)
            self.assertIn("error: preview destination must differ from source", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_deleted_allocation_all_unallocated(self):
        volume = self._allocation_volume(bytes(2))
        result = volume.assess_data_allocation(Attribute(
            0x80, "", 0, 1, False, runs=[DataRun(3, 2, 0)], data_size=1024,
            initialized_size=1024))
        self.assertEqual(result.status, "unallocated")
        self.assertEqual((result.allocated_clusters, result.unallocated_clusters), (0, 2))
        self.assertTrue(any("does not prove" in warning for warning in result.warnings))

    def test_deleted_allocation_all_allocated(self):
        volume = self._allocation_volume(b"\xff\xff")
        result = volume.assess_data_allocation(Attribute(
            0x80, "", 0, 1, False, runs=[DataRun(3, 2, 0)], data_size=1024,
            initialized_size=1024))
        self.assertEqual(result.status, "allocated")
        self.assertEqual((result.allocated_clusters, result.unallocated_clusters), (2, 0))
        self.assertTrue(any("potential reuse" in warning for warning in result.warnings))

    def test_deleted_allocation_mixed_fragmented_runs(self):
        bitmap = bytearray(2); bitmap[3 // 8] |= 1 << (3 & 7)
        volume = self._allocation_volume(bytes(bitmap))
        result = volume.assess_data_allocation(Attribute(
            0x80, "", 0, 1, False,
            runs=[DataRun(3, 1, 0), DataRun(9, 1, 1)], data_size=1024,
            initialized_size=1024))
        self.assertEqual(result.status, "mixed")
        self.assertEqual((result.allocated_clusters, result.unallocated_clusters), (1, 1))

    def test_deleted_allocation_sparse_runs_are_separate(self):
        volume = self._allocation_volume(bytes(2))
        result = volume.assess_data_allocation(Attribute(
            0x80, "", 0, 1, False, runs=[DataRun(None, 2, 0)], data_size=1024,
            initialized_size=1024))
        self.assertEqual(result.status, "unallocated")
        self.assertEqual(result.sparse_clusters, 2)
        self.assertEqual(result.checked_clusters, 0)

    def test_deleted_allocation_multiple_data_extents(self):
        volume = self._allocation_volume(bytes(2))
        record = self._data_record(12, 0, [DataRun(1, 1, 0), DataRun(4, 1, 1)])
        record.attrs.append(dataclasses.replace(record.attrs[0], instance=2,
                                                runs=[DataRun(6, 1, 2)]))
        merged = volume._merged_attribute(record, 0x80, "")
        result = volume.assess_data_allocation(merged)
        self.assertEqual(result.status, "unallocated")
        self.assertEqual(result.unallocated_clusters, 3)

    def test_deleted_allocation_missing_or_incomplete_bitmap_is_unknown(self):
        missing = self._allocation_volume(None, bitmap_error="unable to read $Bitmap")
        attr = Attribute(0x80, "", 0, 1, False, runs=[DataRun(1, 1, 0)], data_size=512)
        self.assertEqual(missing.assess_data_allocation(attr).status, "unknown")
        incomplete = self._allocation_volume(b"\0", total_clusters=16)
        result = incomplete.assess_data_allocation(attr)
        self.assertEqual(result.status, "unknown")
        self.assertTrue(any("incomplete" in warning for warning in result.warnings))

    def test_deleted_resident_data_is_not_applicable_and_recovers(self):
        payload = b"resident-deleted"
        record = FileRecord(
            49, b"", 2, 0,
            [Attribute(0x80, "", 0, 1, True, value=payload)], [],
        )

        class RecoveryFixture(NTFSVolume):
            def __init__(self):
                self._records = [record]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0
                self.f = io.BytesIO()
                self._owned = False
                self._mft_runs = None
                self._bitmap_cache = None
                self._bitmap_error = "bitmap unavailable"

            def iter_mft(self, include_deleted=True, limit=None):
                return iter(self._records)

        volume = RecoveryFixture()
        assessment = volume.assess_data_allocation(record.attrs[0])
        self.assertEqual(assessment.status, "not_applicable")
        with tempfile.TemporaryDirectory() as temp:
            result = volume.recover_selected(temp, records=[49], include_deleted=True)
            self.assertEqual(result[0]["status"], "recovered")
            self.assertEqual(result[0]["allocation_status"], "not_applicable")
            self.assertFalse(result[0]["override_used"])
            outputs = [path for path in Path(temp).iterdir() if path.name != "recovery-log.jsonl"]
            self.assertEqual(len(outputs), 1)
            self.assertEqual(outputs[0].read_bytes(), payload)
            self.assertEqual(hashlib.sha256(outputs[0].read_bytes()).hexdigest(),
                             hashlib.sha256(payload).hexdigest())

    def test_deleted_discovery_finds_unindexed_nonresident_file_and_recovers(self):
        first = b"A" * 512
        second = b"B" * 188
        runs = [DataRun(3, 1, 0), DataRun(7, 1, 1)]
        attr = Attribute(0x80, "", 0, 1, False, runs=runs, data_size=700,
                         initialized_size=700, lowest_vcn=0, highest_vcn=1)
        record = FileRecord(60, b"", 4, 0, [attr], [])
        malformed = FileRecord(
            61, b"", 5, 0,
            [dataclasses.replace(attr, runs=[DataRun(3, 1, 0), DataRun(7, 1, 2)])],
            [],
        )

        class RecoveryFixture(NTFSVolume):
            def __init__(self):
                raw = bytearray(8 * 512)
                raw[3 * 512:4 * 512] = first
                raw[7 * 512:8 * 512] = second + b"\0" * (512 - len(second))
                self._records = [record, malformed]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0
                self.f = io.BytesIO(bytes(raw))
                self._owned = False
                self._mft_runs = None
                self._bitmap_cache = bytes(2)
                self._bitmap_error = None

            def iter_mft(self, include_deleted=True, limit=None):
                return iter(self._records)

        volume = RecoveryFixture()
        discovered = list(volume.discover_deleted_files())
        self.assertEqual(len(discovered), 1)
        self.assertIsInstance(discovered[0], DeletedFileDiscovery)
        self.assertEqual(discovered[0].record.number, 60)
        self.assertEqual(discovered[0].allocation.status, "unallocated")
        with tempfile.TemporaryDirectory() as temp:
            result = volume.recover_selected(temp, records=[60], include_deleted=True)
            self.assertEqual(result[0]["status"], "recovered")
            output = next(Path(temp).glob("record-60"))
            expected = first + second
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),
                             hashlib.sha256(expected).hexdigest())

    def test_mixed_resident_and_nonresident_data_remains_conservative(self):
        resident = Attribute(0x80, "", 0, 1, True, value=b"resident")
        nonresident = Attribute(0x80, "", 0, 2, False,
                                runs=[DataRun(1, 1, 0)], data_size=512,
                                initialized_size=512)
        record = FileRecord(52, b"", 1, 0, [resident, nonresident], [])

        class RecoveryFixture(NTFSVolume):
            def __init__(self):
                self._records = [record]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0
                self.f = io.BytesIO()
                self._owned = False
                self._mft_runs = None
                self._bitmap_cache = None
                self._bitmap_error = "bitmap unavailable"

            def iter_mft(self, include_deleted=True, limit=None):
                return iter(self._records)

        volume = RecoveryFixture()
        with self.assertRaises(ValueError):
            volume.recover(record)
        with tempfile.TemporaryDirectory() as temp:
            result = volume.recover_selected(temp, records=[52], include_deleted=True)
            self.assertEqual(result[0]["status"], "skipped")
            self.assertEqual(result[0]["allocation_status"], "unknown")
            self.assertEqual(list(Path(temp).glob("record-*")), [])

    def test_cluster_allocated_returns_unknown_for_unavailable_bits(self):
        volume = self._allocation_volume(bytes(1), total_clusters=8)
        self.assertIs(volume.cluster_allocated(-1), None)
        self.assertIs(volume.cluster_allocated(8), None)
        self.assertIs(volume.cluster_allocated(0), False)
        volume._bitmap_cache = b"\x01"
        self.assertIs(volume.cluster_allocated(0), True)
        volume._bitmap_cache = None
        volume._bitmap_error = "bitmap unavailable"
        self.assertIs(volume.cluster_allocated(0), None)

    def test_bitmap_geometry_uses_sectors_per_cluster(self):
        volume = self._allocation_volume(b"\0", total_clusters=17)
        volume.geometry = VolumeGeometry(512, 8, 17, 1, 2, -10, -9)
        self.assertIs(volume.cluster_allocated(2), False)
        self.assertIs(volume.cluster_allocated(3), None)
        complete = Attribute(0x80, "", 0, 1, False,
                             runs=[DataRun(2, 1, 0)], data_size=4096,
                             initialized_size=4096)
        self.assertEqual(volume.assess_data_allocation(complete).status, "unallocated")
        out_of_range = dataclasses.replace(complete, runs=[DataRun(3, 1, 0)])
        self.assertEqual(volume.assess_data_allocation(out_of_range).status, "unknown")

    def test_cached_bitmap_shorter_than_geometry_is_rejected(self):
        volume = self._allocation_volume(b"\0", total_clusters=65)
        volume.geometry = VolumeGeometry(512, 8, 65, 1, 2, -10, -9)
        with self.assertRaises(ValueError):
            volume.volume_bitmap()

    def test_read_runs_rejects_gaps_and_short_reads(self):
        volume = self._allocation_volume(bytes(2))
        volume.f = io.BytesIO(b"A" * (4 * volume.geometry.cluster_size))
        with self.assertRaises(ValueError):
            volume.read_runs([DataRun(1, 1, 0), DataRun(2, 1, 2)], 2 * 512)
        volume.f = io.BytesIO(b"A" * volume.geometry.cluster_size)
        with self.assertRaises(IOError):
            volume.read_runs([DataRun(0, 2, 0)], 2 * 512)

    def test_read_runs_preserves_fragmented_sparse_and_multiple_extents(self):
        volume = self._allocation_volume(bytes(2))
        raw = bytearray(4 * volume.geometry.cluster_size)
        raw[volume.geometry.cluster_size:2 * volume.geometry.cluster_size] = b"B" * volume.geometry.cluster_size
        raw[3 * volume.geometry.cluster_size:4 * volume.geometry.cluster_size] = b"D" * volume.geometry.cluster_size
        volume.f = io.BytesIO(bytes(raw))
        result = volume.read_runs([
            DataRun(1, 1, 0), DataRun(None, 1, 1), DataRun(3, 1, 2)
        ], 3 * volume.geometry.cluster_size)
        self.assertEqual(result, b"B" * 512 + b"\0" * 512 + b"D" * 512)

    def test_deleted_override_does_not_bypass_run_integrity(self):
        volume = self._allocation_volume(b"\xff\xff")
        volume.f = io.BytesIO(b"A" * (4 * volume.geometry.cluster_size))
        record = self._data_record(24, 0, [DataRun(1, 1, 0), DataRun(2, 1, 2)])
        with self.assertRaises(ValueError):
            volume.recover(record, allow_deleted_uncertain=True)

    def test_deleted_recovery_conservatively_skips_uncertain_allocation(self):
        class RecoveryFixture(NTFSVolume):
            def __init__(self, record, bitmap, bitmap_error=None):
                self._records = [record]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0
                self.f = io.BytesIO()
                self._owned = False
                self._mft_runs = None
                self._bitmap_cache = bitmap
                self._bitmap_error = bitmap_error

            def iter_mft(self, include_deleted=True, limit=None):
                return iter(self._records if include_deleted else [r for r in self._records if r.in_use])

            def iter_attribute_chunks(self, attr, chunk_size=1024 * 1024):
                yield b"recovered-bytes"

        mixed = bytearray(2); mixed[0] |= 1 << 1
        for bitmap, runs in ((b"\xff\xff", [DataRun(1, 1, 0)]),
                             (bytes(mixed), [DataRun(1, 1, 0), DataRun(9, 1, 1)])):
            record = self._data_record(20, 0, runs)
            with tempfile.TemporaryDirectory() as temp:
                result = RecoveryFixture(record, bitmap).recover_selected(temp)
                self.assertEqual(result[0]["status"], "skipped-allocation")
                self.assertEqual([path.name for path in Path(temp).glob("**/*")], ["recovery-log.jsonl"])
        record = self._data_record(20, 0, [DataRun(1, 1, 0)])
        with tempfile.TemporaryDirectory() as temp:
            result = RecoveryFixture(record, bytes(2)).recover_selected(temp)
            self.assertEqual(result[0]["status"], "recovered")
        record = self._data_record(21, 0, [DataRun(1, 1, 0)])
        with tempfile.TemporaryDirectory() as temp:
            result = RecoveryFixture(record, None, "missing").recover_selected(temp)
            self.assertEqual(result[0]["allocation_status"], "unknown")
            self.assertEqual(result[0]["status"], "skipped-allocation")

    def test_deleted_recovery_override_is_logged(self):
        class RecoveryFixture(NTFSVolume):
            def __init__(self, record):
                self._records = [record]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0; self.f = io.BytesIO(); self._owned = False
                self._mft_runs = None; self._bitmap_cache = b"\xff\xff"; self._bitmap_error = None
            def iter_mft(self, include_deleted=True, limit=None): return iter(self._records)
            def iter_attribute_chunks(self, attr, chunk_size=1024 * 1024): yield b"data"
            def read_runs(self, runs, size, start_vcn=0): return b"data"

        with tempfile.TemporaryDirectory() as temp:
            volume = RecoveryFixture(self._data_record(22, 0, [DataRun(1, 1, 0)]))
            with self.assertRaises(ValueError):
                volume.recover(volume._records[0])
            result = volume.recover_selected(temp, allow_deleted_uncertain=True)
            self.assertEqual(result[0]["status"], "recovered")
            self.assertTrue(result[0]["override_used"])

    def test_active_recovery_ignores_deleted_allocation_gate(self):
        class RecoveryFixture(NTFSVolume):
            def __init__(self, record):
                self._records = [record]
                self.geometry = VolumeGeometry(512, 1, 16, 1, 2, -10, -9)
                self.offset = 0; self.f = io.BytesIO(); self._owned = False
                self._mft_runs = None; self._bitmap_cache = b"\xff\xff"; self._bitmap_error = None
            def iter_mft(self, include_deleted=True, limit=None): return iter(self._records)
            def iter_attribute_chunks(self, attr, chunk_size=1024 * 1024): yield b"active-data"

        with tempfile.TemporaryDirectory() as temp:
            result = RecoveryFixture(self._data_record(23, 1, [DataRun(1, 1, 0)])).recover_selected(temp)
            self.assertEqual(result[0]["status"], "recovered")
            self.assertEqual(result[0]["allocation_status"], "not-assessed")

    def test_fixup_restores_sector_tails(self):
        r = bytearray(1024); r[:4] = b"FILE"; struct.pack_into("<HH", r, 4, 0x30, 3)
        r[0x30:0x36] = b"\xaa\xbb\x10\x00\x20\x00"; r[510:512] = r[1022:1024] = b"\xaa\xbb"
        self.assertEqual(apply_fixup(bytes(r))[510:512], b"\x10\x00")
        self.assertEqual(apply_fixup(bytes(r))[1022:1024], b"\x20\x00")

    def test_boot_geometry_signed_sizes(self):
        b = bytearray(512); b[3:11] = b"NTFS    "; struct.pack_into("<HB", b, 0x0b, 512, 8); struct.pack_into("<QQQ", b, 0x28, 10000, 4, 8); struct.pack_into("<b", b, 0x40, -10); struct.pack_into("<b", b, 0x44, -10); b[0x1fe:0x200] = b"\x55\xaa"
        g = VolumeGeometry.from_boot_sector(bytes(b)); self.assertEqual(g.cluster_size, 4096); self.assertEqual(g.record_size, 1024); self.assertEqual(g.index_size, 1024)

    def test_invalid_boot_rejected(self):
        with self.assertRaises(ValueError): VolumeGeometry.from_boot_sector(b"x" * 512)

    def test_volume_rejects_non_ntfs(self):
        with self.assertRaises(ValueError): NTFSVolume(io.BytesIO(b"x" * 1024))

    def test_index_entry_file_name(self):
        # One minimal FILE_NAME key and an end marker, using an INDEX_ROOT-style header.
        name = "a".encode("utf-16le")
        key = bytearray(0x42 + len(name)); struct.pack_into("<Q", key, 0, 7); key[0x40:0x42] = b"\x01\x01"; key[0x42:] = name
        entry_len = (0x10 + len(key) + 7) & ~7
        value = bytearray(8 + 0x20 + entry_len + 0x10)
        struct.pack_into("<III", value, 8 + 0x10, 0x20, 0x20 + entry_len, 0x20 + entry_len)
        struct.pack_into("<QHHI", value, 8 + 0x20, 7, entry_len, len(key), 0)
        value[8 + 0x20 + 0x10:8 + 0x20 + 0x10 + len(key)] = key
        pos = 8 + 0x20 + entry_len; struct.pack_into("<QHHI", value, pos, 0, 0x10, 0, 2)
        entries = parse_index_entries(bytes(value), 8)
        self.assertEqual(entries[0].file_reference, 7); self.assertEqual(entries[0].key.name, "a")

    def test_data_attribute_resident(self):
        record = bytearray(0x80); record[0x14:0x18] = struct.pack("<I", 0x18)
        struct.pack_into("<IIBBHH", record, 0x18, 0x80, 0x40, 0, 0, 0, 1)
        struct.pack_into("<IHH", record, 0x28, 3, 0x38, 0)
        record[0x50:0x53] = b"abc"; record[0x58:0x5c] = struct.pack("<I", 0xffffffff)
        attrs = parse_attributes(bytes(record)); self.assertEqual(attrs[0].value, b"abc")


if __name__ == "__main__": unittest.main()
