# End-to-end reliability audit

The audit covered the existing pipeline without physical-device access:

```text
python3 -m py_compile src/ntfs_recovery.py fixtures/generate_deleted_vhdx_fixture.py tests/test_ntfs_recovery.py tests/test_synthetic_ntfs_image.py tests/test_deleted_vhdx_fixture.py tests/test_vhdx_reader.py
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

Result: 22 focused tests passed. A follow-up candidate-to-VHDX integration
pass ran 5 focused tests successfully.

## Verified capabilities

The candidate validator, MFT traversal, deleted-record discovery, mapping-pair
validation, `$Bitmap` assessment, streaming extraction, destination security,
manifest revalidation, and output hashing are covered by synthetic raw and
VHDX fixtures. The deleted VHDX fixture recovers a fragmented deleted
nonresident file byte-for-byte while skipping mixed-allocation data.

## Demonstrated limitations

The supplied Windows-created VHDX has no surviving raw FILE records for the
original `Documents/Projects/project-notes.txt` or
`Archive/fragmented-test.bin`. They remain unclaimed and were not used as
recovery targets. Directory-index loss, incomplete `$ATTRIBUTE_LIST` metadata,
cluster reuse, VHDX parent chains, encrypted containers, and physical-device
validation remain outside the verified boundary where source metadata is
insufficient.

No production defect was demonstrated during this audit. The only change was
an additional candidate-validation assertion in the separate deleted VHDX
fixture test; no recovery safety policy was weakened.
