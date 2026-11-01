# v0.1.0-recovery-baseline

The tagged checkpoint commit contains this document and the complete implementation,
fixtures, focused tests, and reports. Reverse-engineering artifacts under
`analysis/` and `decompiled-all/` remain separate and are ignored by Git.

## Deterministic fixture hashes

These values are generated from the committed fixture builders:

| Fixture | Size | SHA-256 |
|---|---:|---|
| Existing synthetic raw image from `build_image()` | 1,048,576 bytes | `7a9c064c255d81cf2fa27f19f75521eec5752cb2af2b24a936920f9651fe3788` |
| Separate deleted-file VHDX from `build_fixture()` | 6,291,456 host bytes; 1,048,576 virtual bytes | `e4acda5927e5cfd42a50e3390a6e22d3d997dbdb6df7c86338596ece0989a208` |

The supplied Windows-created VHDX is not copied into the repository and is
kept outside the generated fixture set.

## Fixture generation

```text
PYTHONPATH=. python3 - <<'PY'
import hashlib
from fixtures.generate_ntfs_test_image import build_image
from fixtures.generate_deleted_vhdx_fixture import build_fixture
raw, _ = build_image()
vhdx, _ = build_fixture()
print(hashlib.sha256(raw).hexdigest())
print(hashlib.sha256(vhdx).hexdigest())
PY

tmpdir=$(mktemp -d /tmp/deleted-vhdx-fixture.XXXXXX)
python3 fixtures/generate_deleted_vhdx_fixture.py \
  --image "$tmpdir/deleted-fixture.vhdx" \
  --manifest "$tmpdir/deleted-fixture.json"
rm -rf "$tmpdir"
```

## Focused validation checkpoint

```text
python3 -m py_compile \
  src/ntfs_recovery.py \
  fixtures/generate_deleted_vhdx_fixture.py \
  tests/test_ntfs_recovery.py \
  tests/test_synthetic_ntfs_image.py \
  tests/test_deleted_vhdx_fixture.py \
  tests/test_vhdx_reader.py
python3 -m unittest -v \
  tests.test_vhdx_reader \
  tests.test_synthetic_ntfs_image \
  tests.test_deleted_vhdx_fixture \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_easeus_dbr_predicate_rules \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_preserves_intra_cluster_and_fragmented_mft_offsets \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_short_mft_extent_fails_safely \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_discovery_finds_unindexed_nonresident_file_and_recovers \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_all_unallocated \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_all_allocated \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_mixed_fragmented_runs \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_recovery_conservatively_skips_uncertain_allocation \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_override_does_not_bypass_run_integrity \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_manifest_is_canonical_and_tamper_detected \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_manifest_recovery_revalidates_and_hashes_output \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_secure_destination_rejects_symlinks_traversal_and_source_filesystem \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_pinned_source_descriptor_survives_replacement_and_detects_mutation \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_secure_destination_closes_on_success_and_exception \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_secure_log_rejects_symlink_and_existing_collision \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_failed_recovery_removes_partial_output
```

Recorded result: 22 focused reliability tests passed; the follow-up
candidate/VHDX integration slice passed 5 tests. No physical device was
accessed, and no source VHDX was modified.
