# Deleted nonresident VHDX fixture validation

This fixture is separate from the supplied Windows-created VHDX and from the
existing raw synthetic image. The original fixture evidence was not changed.
The generator starts with the existing deterministic NTFS-like image and adds
record 16, `\Documents\deleted-vhdx.bin`, with a deleted FILE record, a
fragmented unnamed nonresident DATA stream, and source clusters that remain
unallocated in `$Bitmap`.

The original missing `project-notes.txt` and `fragmented-test.bin` targets were
not added or treated as recoverable.

## Generation

```text
tmpdir=$(mktemp -d /tmp/deleted-vhdx-fixture.XXXXXX)
python3 fixtures/generate_deleted_vhdx_fixture.py \
  --image "$tmpdir/deleted-fixture.vhdx" \
  --manifest "$tmpdir/deleted-fixture.json"
rm -rf "$tmpdir"
```

The generated VHDX had virtual size 1,048,576 bytes and deterministic SHA-256:

```text
e4acda5927e5cfd42a50e3390a6e22d3d997dbdb6df7c86338596ece0989a208
```

## Focused validation

```text
python3 -m py_compile \
  fixtures/generate_deleted_vhdx_fixture.py \
  src/ntfs_recovery.py \
  tests/test_deleted_vhdx_fixture.py \
  tests/test_synthetic_ntfs_image.py
python3 -m unittest -v \
  tests.test_deleted_vhdx_fixture \
  tests.test_synthetic_ntfs_image.SyntheticNTFSImageTests.test_deleted_discovery_is_independent_of_directory_indexes \
  tests.test_vhdx_reader.VHDXReaderTests.test_metadata_bat_bitmap_and_boundaries
```

Result: `Ran 3 tests in 2.145s — OK`.

Validated record 16:

| Field | Result |
|---|---|
| Deleted state | FILE flags `0x0` |
| Sequence number | `2` |
| DATA form | Unnamed nonresident |
| Mapping pairs | LCN 340 / VCN 0 and LCN 345 / VCN 1 |
| Allocation status | `unallocated` |
| Recovery status | `recovered`, without allocation override |
| Output | 1,024 bytes |
| SHA-256 | Matched the generated manifest |

The test uses `VHDXReader` and the normal `NTFSVolume.discover_deleted_files()`
and `recover_selected()` paths. It also verifies that the two original
missing target names are absent from discovery. The source VHDX is generated
in a temporary directory, opened read-only by the reader, and never modified
during validation. No physical device was accessed.
