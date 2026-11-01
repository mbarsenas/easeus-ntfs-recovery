# Formatter-created NTFS fixture validation

The workflow is implemented in
`fixtures/generate_real_ntfs_fixture.py`. It is restricted to regular image
files and uses `mkntfs` plus a user-space `ntfs-3g` mount to create nested
directories, copy known files, delete one file, unmount, and run the existing
candidate validation, inventory, and preview code.

Current environment result:

- `mkntfs`: installed at `/usr/sbin/mkntfs`.
- `ntfscp`, `ntfsls`, and `ntfsinfo`: installed.
- `ntfs-3g`: installed at `/usr/bin/ntfs-3g`, but unusable because `/dev/fuse`
  is absent/inaccessible.
- `ntfsmkdir`/`ntfsrm`: unavailable.
- Non-root kernel mounting of the image is unavailable.

Therefore the complete formatter/populate/delete validation was not claimed
or run. The script writes a `blocked` JSON report and planned test manifest
when the population backend is unavailable; it does not create a misleading
partial fixture. The existing synthetic benchmark remains unchanged.

When `ntfs-3g` is available, run:

```text
python3 fixtures/generate_real_ntfs_fixture.py \
  --image /tmp/real-ntfs-fixture.img \
  --manifest /tmp/real-ntfs-fixture.json \
  --report /tmp/real-ntfs-fixture-report.json
```

The manifest contains original paths, sizes, and SHA-256 hashes. Deleted-file
success is only accepted when recovered output hashes equal the recorded
hash. The current parser is expected to recognize boot geometry, MFT record 0,
MFT runs, FILE_NAME paths, and deleted-record visibility; directory-index
interpretation is reported separately because the inventory API does not expose
an independent index-recognition result.

Focused execution here returned exit status 2 with `status: blocked` and
created no image because `/dev/fuse` is unavailable. No preview or inventory
run was attempted against an unpopulated image.

## Bounded real-fixture validation

The following read-only command was used against the supplied VHDX; it reads
the primary DBR, the GPT/NTFS boundary sectors, and the MFT-backed inventory
only:

```text
PYTHONPATH=. python3 - <<'PY'
from src.ntfs_recovery import VHDXReader, NTFSVolume, is_easeus_ntfs_boot_sector, u16, u64

path = "/path/to/ntfs-recovery-test.vhdx"
partition = 0x01000000
with VHDXReader(path) as source:
    boot = source.read_at(partition, 512)
    bps, spc = u16(boot, 0x0b), boot[0x0d]
    total = u64(boot, 0x28)
    backup = partition + (total - 1) * bps
    print(hex(backup), is_easeus_ntfs_boot_sector(source.read_at(backup, 512)))
    with NTFSVolume(source, offset=partition) as volume:
        print(volume.geometry)
        print(len(volume.inventory(include_deleted=True)))
PY
```

Observed primary geometry:

| Field | Value |
|---|---:|
| Partition offset | `0x01000000` |
| Bytes/sector | `512` |
| Sectors/cluster | `8` |
| Total sectors in DBR | `4,161,407` |
| `$MFT` LCN | `173392` |
| `$MFTMirr` LCN | `2` |
| Volume byte length from DBR | `2,130,640,384` |

The DBR-derived backup location is:

```text
0x01000000 + (4,161,407 - 1) * 512 = 0x7FFEFC00
```

That sector and the preceding sector are zero-filled and fail the NTFS
predicate. The next sector, `0x7FFEFE00`, contains a valid NTFS boot sector.
The GPT data partition spans LBAs `32768..4194175`; its last sector is
`0x7FFEFE00`. Thus the image has a one-sector discrepancy: the DBR's total
sector field leads to `0x7FFEFC00`, while the partition boundary and actual
backup DBR are at `0x7FFEFE00`. This is an inconsistent formatter/image
layout, not a reader offset-calculation error. Validation was not weakened.

## Inventory result

The MFT mapping pairs are `(LCN 173392, length 64 clusters)`, yielding 256
1 KiB record slots. The existing parser returned 48 valid records; records
16–23 and 56–255 had no valid FILE metadata. Grouped below are every returned
record and path (ranges indicate identical duplicate observations):

| MFT record(s) | Status | Path | Size |
|---|---|---|---:|
| 0–3 | active | `\$MFT` | 262144 |
| 4–7 | active | `\$AttrDef` | 2560 |
| 8–11 | active | `\$BadClus` | 0 |
| 12–15 | active | `\` | 0 |
| 24–27 | active | `\$BadClus\$Quota` | 0 |
| 28–31 | active | `\$BadClus\$Quota\$Repair` | 0 |
| 32–35 | active | `\$BadClus\$Quota\$Repair\$Tops` | 100 |
| 36–39 | active | `\System Volume Information` | 0 |
| 40–43 | active | `\System Volume Information\Documents` | 0 |
| 44–47 | active | `\System Volume Information\ClientRecoveryPasswordRotation` | 0 |
| 48–51 | active | `\System Volume Information\Documents\photo-2.txt` | 19 |
| 52–55 | active | `\$RECYCLE.BIN` | 0 |

None of the requested deleted targets were found:

- `Documents/Projects/project-notes.txt`: missing.
- `Archive/fragmented-test.bin`: missing.
- `Photos/photo-3.txt`: missing.

The five surviving control files could not be identified in the returned MFT
inventory. A stale `$I30` entry references `Projects` and `resident-test.txt`,
but the corresponding MFT slot contains unrelated `Documents` metadata.
This, together with four identical observations for many records, is stale or
ambiguous directory/MFT metadata rather than evidence of recoverable targets.

## Bitmap and deleted allocation evidence

`NTFSVolume.volume_bitmap()` returned 2,560 bytes by reading record 6, but the
DBR geometry requires approximately 4 MiB of bitmap coverage. Record 6 is
identified by the current parser as `$AttrDef`, not `$Bitmap`; therefore the
bitmap evidence is incomplete and cannot safely assess any requested target.
All three deleted-target allocation statuses are consequently **unknown**;
no extraction or allocation-policy override was performed.

The focused validation command and tests used were:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_vhdx_reader.py
python3 -m unittest tests.test_vhdx_reader tests.test_synthetic_ntfs_image tests.test_ntfs_benchmark -v
```

Result:

```text
Ran 5 tests in 0.776s
OK
```

The source VHDX was opened read-only. No writes, mounts, repairs, physical
device reads, `/dev/sdg` access, or broad disk scans were performed.

## Diagnosis of missing files

The original manifest was read from
`/path/to/ntfs-recovery-originals.json`. It lists
eight files: five active controls and three deleted files.

### MFT completeness

The raw `$MFT` record 0 DATA stream is:

```text
VCN 0, LCN 173392, length 64 clusters
```

With 4,096-byte clusters this covers exactly 262,144 bytes. The DBR record
size is 1,024 bytes, so the stream contains 256 record slots. The run has
continuous VCN coverage, nonnegative/in-range LCNs, and exact stream-size
coverage. The diagnostic read traversed all 256 slots; 47 contained `FILE`
signatures and 209 were zero-filled. Thus the MFT is not truncated at the
initial records.

### Record-offset defect in the current reader

`NTFSVolume.read_record()` computes the record byte offset, then calls
`read_runs()` with `start_vcn = offset // cluster_size` and requests only one
record. It does not preserve `offset % cluster_size`. Because the fixture has
four 1 KiB records per 4 KiB cluster, this causes four logical record numbers
to read the first 1 KiB of the same cluster:

```text
logical records 40,41,42,43 -> record 40's bytes
logical records 48,49,50,51 -> record 48's bytes
```

The FILE records are valid and are not rejected by USA, signature, or
attribute parsing. Inventory is therefore reading the wrong physical slice,
not filtering valid records. This is the exact reason the earlier inventory
showed duplicate `Documents` and `photo-2.txt` rows and omitted the deleted
record 49.

### Correctly aligned raw FILE records

The following table was obtained by reading the complete MFT stream once and
parsing each 1 KiB slice at its actual intra-cluster offset:

| Record | State | Sequence | FILE_NAME / parent | DATA |
|---:|---|---:|---|---|
| 39 | active | 1 | `NTFS_RECOVERY_TEST`, parent 5 | directory `$I30` |
| 40 | active | 1 | `Documents`, parent 39 | directory `$I30` |
| 41 | active | 1 | `Projects`, parent 40 | directory `$I30` |
| 42 | active | 1 | `Photos`, parent 39 | directory `$I30` |
| 43 | active | 1 | `Archive`, parent 39 | directory `$I30` |
| 45 | active | 1 | `resident-test.txt`, parent 40 | resident DATA, 80 bytes |
| 47 | active | 1 | `photo-1.txt`, parent 42 | resident DATA, 19 bytes |
| 48 | active | 1 | `photo-2.txt`, parent 42 | resident DATA, 19 bytes |
| 49 | deleted | 2 | `photo-3.txt`, parent 42, parent sequence 1 | resident DATA, 19 bytes |
| 50 | active | 1 | `photo-4.txt`, parent 42 | resident DATA, 19 bytes |
| 51 | active | 1 | `photo-5.txt`, parent 42 | resident DATA, 19 bytes |

The five surviving control files are records 45, 47, 48, 50, and 51. The
deleted `Photos\photo-3.txt` FILE record exists at record 49 but is hidden by
the offset defect. It is resident, so no physical cluster allocation status
can be established for its DATA stream.

No raw FILE record exists for `Documents\Projects\project-notes.txt` or
`Archive\fragmented-test.bin`. Their names occur only in the bounded raw MFT
bytes inside directory-index metadata/search context; their expected FILE
records are absent. They cannot be recovered from MFT metadata by the current
engine without another evidence source.

### Directory indexes

Correctly aligned `$I30` INDEX_ROOT entries show:

| Directory record | Entries present |
|---:|---|
| 39 | `Archive` → 43; `Documents` → 40; `Photos` → 42 |
| 40 | `Projects` → 41; `resident-test.txt` → 45 |
| 41 | no live child entry |
| 42 | `photo-1.txt` → 47; `photo-2.txt` → 48; `photo-4.txt` → 50; `photo-5.txt` → 51 |
| 43 | no live child entry |

The deleted `photo-3.txt` index entry is absent, as expected for a deleted
directory entry, but its FILE record remains. `Projects` and `Archive` have no
live child index entry for the two other deleted targets. There is no evidence
of an INDEX_ALLOCATION requirement for these small directories. The existing
`inventory()` implementation does not independently reconstruct `$I30`; it
uses FILE_NAME metadata and is additionally affected by the record-offset
defect.

### `$ATTRIBUTE_LIST` and bitmap

The correctly aligned expected records have no `$ATTRIBUTE_LIST`; their
attributes are resident FILE_NAME and resident DATA. The directory records
also expose resident `$I30` roots. No extension-record chain is needed to
explain these omissions.

The correctly aligned raw record 6 is `$Bitmap` with a nonresident DATA stream
of 65,024 bytes at LCN 173375, length 16 clusters. The current
`volume_bitmap()` calls the defective `read_record(6)` and consequently reads
record 4 (`$AttrDef`) instead. Even after correcting record addressing, the
65,024-byte bitmap is far shorter than the approximately 4,161,407 bytes
required by the DBR geometry, so allocation evidence would remain incomplete.
The three target statuses are therefore conservatively `unknown`; no
extraction or allocation override was performed.

### Recommended smallest corrective change

Do not change boot validation, geometry, deletion policy, or directory-name
rules. Correct only `read_record()` so it reads from the containing cluster
and discards the intra-cluster prefix, for example by requesting
`record_size + (offset % cluster_size)` bytes and slicing off that prefix.
Then rerun inventory. This should expose records 45, 47–51 and their FILE_NAME
paths, while the two targets with no raw FILE record will still correctly
remain unresolved. This recommendation is diagnostic only; no production
parser change was made in this task.

## MFT offset correction validation

Implemented the minimal correction in `NTFSVolume.read_record()`. It now
rejects negative and out-of-range logical record numbers, preserves the
intra-cluster prefix, reads through the existing fragmented `read_runs()`
mapping, and slices the requested record after the read. Records crossing
cluster boundaries are supported.

Focused commands run:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_ntfs_recovery.py
python3 -m unittest \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_preserves_intra_cluster_and_fragmented_mft_offsets \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_short_mft_extent_fails_safely \
  tests.test_vhdx_reader tests.test_synthetic_ntfs_image -v
```

Result:

```text
Ran 6 tests in 0.930s
OK
```

After the fix, targeted inventory returns:

| Record | State | Path | Size |
|---:|---|---|---:|
| 39 | active | `\NTFS_RECOVERY_TEST` | 0 |
| 40 | active | `\NTFS_RECOVERY_TEST\Documents` | 0 |
| 41 | active | `\NTFS_RECOVERY_TEST\Documents\Projects` | 0 |
| 42 | active | `\NTFS_RECOVERY_TEST\Photos` | 0 |
| 43 | active | `\NTFS_RECOVERY_TEST\Archive` | 0 |
| 45 | active | `\NTFS_RECOVERY_TEST\Documents\resident-test.txt` | 80 |
| 47 | active | `\NTFS_RECOVERY_TEST\Photos\photo-1.txt` | 19 |
| 48 | active | `\NTFS_RECOVERY_TEST\Photos\photo-2.txt` | 19 |
| 49 | deleted | `\NTFS_RECOVERY_TEST\Photos\photo-3.txt` | 19 |
| 50 | active | `\NTFS_RECOVERY_TEST\Photos\photo-4.txt` | 19 |
| 51 | active | `\NTFS_RECOVERY_TEST\Photos\photo-5.txt` | 19 |

The existing raw-image behavior is preserved: this is generic logical MFT
stream addressing and does not assume contiguous storage. The two other
deleted targets remain unresolved because no raw FILE records exist for
`Documents\Projects\project-notes.txt` or `Archive\fragmented-test.bin`, and
their directory indexes have no live child entries. Record 49 is represented
as deleted, but its resident DATA allocation status remains `unknown` because
the fixture's `$Bitmap` stream is incomplete. No extraction or allocation
override was performed.

## Read-only forensic assessment: `Photos\photo-3.txt`

Record 49 was inspected directly through `VHDXReader` and the corrected
`NTFSVolume.read_record()` implementation. No recovery API was called and no
output file was created.

Record metadata:

| Field | Observed value |
|---|---|
| MFT record | 49 |
| FILE flags | `0x0000` (not in use/deleted) |
| Sequence number | 2 |
| FILE_NAME | `photo-3.txt` |
| Parent reference | record 42, parent sequence 1 |
| DATA form | resident unnamed DATA |
| Resident value length | 19 bytes |
| Nonresident mapping pairs | none; no physical clusters are referenced |

The resident DATA value was read into memory only. Its digest was:

```text
length: 19
sha256: ecab875a6f631eb357705cdaa1e470cda266df8a02b53a8c04a8bc0b4bc1a602
```

The manifest expects length `19` and SHA-256
`ECAB875A6F631EB357705CDAA1E470CDA266DF8A02B53A8C04A8BC0B4BC1A602`.
The comparison is an exact match. This establishes that the deleted FILE
record still contains the original resident DATA bytes; it is not a claim
that a nonresident cluster was safely recovered.

Allocation assessment is `unknown`, with the explicit warning that resident
DATA has no source clusters to assess. The available `$Bitmap` stream is
65,024 bytes while the geometry requires at least 4,161,407 bytes, so bitmap
completeness cannot be established. No allocation override was used.

Diagnostic command:

```text
PYTHONPATH=. python3 - <<'PY'
# Open the VHDX read-only, inspect record 49, hash its resident DATA in memory,
# and compare it with ntfs-recovery-originals.json; no recovery/output call.
PY
```

Focused tests run:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_ntfs_recovery.py tests/test_vhdx_reader.py
python3 -m unittest \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_preserves_intra_cluster_and_fragmented_mft_offsets \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_short_mft_extent_fails_safely \
  tests.test_vhdx_reader -v
```

Result: `Ran 5 tests in 0.902s — OK`.

## Normal API recovery attempt: deleted resident `photo-3.txt`

The normal selected-recovery API was invoked for record 49 with
`include_deleted=True`, without `allow_deleted_uncertain`, and with a new
temporary `/dev/shm` destination:

```text
with VHDXReader(source) as reader:
    with NTFSVolume(reader, offset=0x01000000) as volume:
        result = volume.recover_selected(
            destination, records=[49], include_deleted=True
        )
```

The exact result was:

```json
{
  "source_record": 49,
  "source_path": "\\NTFS_RECOVERY_TEST\\Photos\\photo-3.txt",
  "status": "skipped-allocation",
  "allocation_status": "unknown",
  "allocation_warnings": ["resident DATA has no source clusters to assess"],
  "error": "deleted-file allocation is not conservatively safe",
  "override_used": false,
  "destination": null,
  "size": 19
}
```

Only the JSONL recovery log was created; no recovered output file was
written. This is the expected conservative behavior. The normal API does not
special-case resident deleted DATA, and no allocation-policy bypass was added.
The previously verified in-memory resident DATA hash remains an exact match,
but normal recovery correctly refuses to label it safe when allocation status
is unknown.

Focused tests rerun after this attempt:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_ntfs_recovery.py tests/test_vhdx_reader.py
python3 -m unittest \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_preserves_intra_cluster_and_fragmented_mft_offsets \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_read_record_short_mft_extent_fails_safely \
  tests.test_vhdx_reader -v
```

Result: `Ran 5 tests in 0.918s — OK`.

## Active-file byte-exact extraction

The five active files were selected by corrected inventory record number and
recovered through the existing `VHDXReader` → `NTFSVolume` →
`recover_selected()` path. The destination was a new temporary `/dev/shm`
directory, separate from the source VHDX. Deleted records were excluded with
`include_deleted=False`.

Command:

```text
tmpdest=$(mktemp -d /dev/shm/ntfs-active-recovery.XXXXXX)
PYTHONPATH=. python3 - <<'PY' "$tmpdest" \
  "/path/to/ntfs-recovery-test.vhdx" \
  "/path/to/ntfs-recovery-originals.json"
# Select records 45, 47, 48, 50, 51; recover with include_deleted=False;
# compare output size and SHA-256 against the manifest.
PY
rm -rf "$tmpdest"
```

Results:

| File | Record | Size | SHA-256 | Result |
|---|---:|---:|---|---|
| `Documents/resident-test.txt` | 45 | 80 | `7eafa628510ff1d24d560d0c71c5cc3aad97a40a661120b51a9bf5e5885f9bc5` | PASS |
| `Photos/photo-1.txt` | 47 | 19 | `4e6e312c67d28a5dc64048970a3d714f6cbbf10f840173352be4d7c0c01ca968` | PASS |
| `Photos/photo-2.txt` | 48 | 19 | `c13318262ea7790dfe38dd5eebdebbeb2a50b52f923d9a9dd199214f4b1b7351` | PASS |
| `Photos/photo-4.txt` | 50 | 19 | `a9be369daec7b4abd551a3a735229edb33e09888ec05f840256afabb3fc4252a` | PASS |
| `Photos/photo-5.txt` | 51 | 19 | `f999faf0e8451fe5ef445deca146e547e5c78417e36973ee81b888e7c2dcd2b` | PASS |

The output tree contained exactly the five expected files beneath
`NTFS_RECOVERY_TEST/`; no unexpected files were extracted. These results
confirm byte-exact active-file recovery only. They make no claim about the
three deleted targets.

## Corrected deleted resident DATA handling

The prior result above exposed an allocation-classification bug: resident
DATA has no source clusters, so requiring `$Bitmap` evidence was not
applicable. The recovery implementation now reports resident DATA as
`not_applicable`. A single complete unnamed resident DATA attribute is
eligible for the normal deleted-file path; nonresident DATA retains the
existing conservative allocation gate. Mixed or ambiguous resident and
nonresident DATA remains unsafe and is skipped.

Changed functions:

- `NTFSVolume.assess_data_allocation()` returns `not_applicable` for resident
  DATA and records that no source clusters require assessment.
- `NTFSVolume._recovery_data_attribute()` resolves one DATA stream and rejects
  mixed resident/nonresident forms as ambiguous.
- `NTFSVolume.recover()` and `NTFSVolume._recover_selected_impl()` allow only
  `unallocated` or `not_applicable` deleted DATA without the explicit
  uncertainty override. Extraction integrity, destination security, and
  collision checks are unchanged.
- `NTFSVolume.inventory()` uses the same stream resolution and reports the
  allocation status and warning.

Focused synthetic validation:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_ntfs_recovery.py tests/test_vhdx_reader.py
python3 -m unittest -v \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_resident_data_is_not_applicable_and_recovers \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_mixed_resident_and_nonresident_data_remains_conservative \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_all_unallocated \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_all_allocated \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_mixed_fragmented_runs \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_missing_or_incomplete_bitmap_is_unknown \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_recovery_conservatively_skips_uncertain_allocation \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_active_recovery_ignores_deleted_allocation_gate \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_override_does_not_bypass_run_integrity
```

Result: `Ran 9 tests in 0.013s — OK`.

A final focused pass also included the resident parser, sparse/fragmented
stream, and active-path regressions: `Ran 11 tests in 0.008s — OK`.

The real fixture was then processed read-only, bounded to record 49, with a
fresh temporary destination and no `allow_deleted_uncertain` override:

```text
dest=$(mktemp -d /tmp/ntfs-photo3-recovery.XXXXXX)
DEST="$dest" PYTHONPATH=. python3 - <<'PY'
from pathlib import Path
from src.ntfs_recovery import VHDXReader, NTFSVolume
source = "/path/to/ntfs-recovery-test.vhdx"
with VHDXReader(source) as reader:
    with NTFSVolume(reader, offset=0x01000000) as volume:
        print(volume.recover_selected(Path(__import__("os").environ["DEST"]),
                                      records=[49], include_deleted=True))
PY
rm -rf "$dest"
```

Result:

| Record | Status | Size | Allocation | Override | SHA-256 |
|---:|---|---:|---|---|---|
| 49 (`Photos/photo-3.txt`) | `recovered` | 19 | `not_applicable` | `false` | `ecab875a6f631eb357705cdaa1e470cda266df8a02b53a8c04a8bc0b4bc1a602` |

Exactly one payload file was created (plus the JSONL recovery log), and its
length and SHA-256 match the original manifest. This confirms normal recovery
of the deleted resident file only; it does not establish recovery of deleted
nonresident files. The source VHDX was not modified, and no physical device
was accessed.

## `$Bitmap` geometry correction

The previous bitmap incompleteness finding was caused by an incorrect cluster
count calculation. NTFS boot-sector field `total_sectors` counts logical
sectors, so the number of clusters is the ceiling of
`total_sectors / sectors_per_cluster`; multiplying by sectors per cluster
overstated the required bitmap size by a factor of eight for this fixture.

Production changes:

- `NTFSVolume.volume_bitmap()` now validates both cached and freshly read
  `$Bitmap` data against the geometry-derived minimum byte count.
- `NTFSVolume.cluster_allocated()` rejects clusters outside the volume's
  derived cluster range as unknown.
- `NTFSVolume.assess_data_allocation()` uses the corrected cluster count when
  validating every non-sparse DATA run.
- Short or unavailable bitmap evidence remains `unknown`; it is never treated
  as free. Extra tail bytes in a bitmap are tolerated because they do not
  reduce coverage of valid volume clusters.

Focused tests:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_ntfs_recovery.py
python3 -m unittest -v \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_bitmap_geometry_uses_sectors_per_cluster \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_cached_bitmap_shorter_than_geometry_is_rejected \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_all_unallocated \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_all_allocated \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_mixed_fragmented_runs \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_sparse_runs_are_separate \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_multiple_data_extents \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_allocation_missing_or_incomplete_bitmap_is_unknown \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_recovery_conservatively_skips_uncertain_allocation
```

Result: `Ran 9 tests in 0.008s — OK`.

Bounded read-only VHDX validation:

```text
PYTHONPATH=. python3 - <<'PY'
from src.ntfs_recovery import VHDXReader, NTFSVolume
with VHDXReader('/path/to/ntfs-recovery-test.vhdx') as reader:
    with NTFSVolume(reader, offset=0x01000000) as volume:
        bitmap = volume.volume_bitmap()
        clusters = (volume.geometry.total_sectors + volume.geometry.sectors_per_cluster - 1) // volume.geometry.sectors_per_cluster
        print(volume.geometry, len(bitmap), (clusters + 7) // 8)
        print(volume.cluster_allocated(clusters))
PY
```

Observed geometry and bitmap evidence:

| Value | Result |
|---|---:|
| Total logical sectors | 4,161,407 |
| Sectors per cluster | 8 |
| Derived cluster count | 520,176 |
| Minimum bitmap bytes | 65,022 |
| `$Bitmap` bytes read | 65,024 |
| Coverage | Complete |
| Out-of-range cluster status | `unknown` |

Sample bitmap bits for the fixture's `$Bitmap` and `$MFT` clusters were read
as allocated. No deleted nonresident file was extracted in this milestone;
the known deleted nonresident targets have no corresponding raw FILE records
in this fixture. The VHDX remained read-only and no physical device was
accessed.

## Deleted nonresident recovery validation

The current implementation and this report were reviewed before a bounded
read-only validation of the established VHDX. The command used was:

```text
PYTHONPATH=. python3 - <<'PY'
# Open ntfs-recovery-test.vhdx with VHDXReader, initialize NTFSVolume at
# 0x01000000, read volume_bitmap(), enumerate the MFT inventory including
# deleted records, inspect the three manifest targets, assess every
# nonresident DATA run, and invoke recover_selected() only if a target has a
# complete FILE/DATA structure and allocation_status == "unallocated".
PY
```

The source was opened only through `VHDXReader`; no physical device was
accessed. The original manifest was read from:

```text
/path/to/ntfs-recovery-originals.json
```

Bitmap revalidation succeeded:

| Geometry/evidence | Value |
|---|---:|
| Total logical sectors | 4,161,407 |
| Sectors per cluster | 8 |
| Derived cluster count | 520,176 |
| Required bitmap bytes | 65,022 |
| Bitmap bytes read | 65,024 |
| Coverage | Complete |

Target results:

| Target | FILE/DATA evidence | Allocation | Recovery | Manifest comparison |
|---|---|---|---|---|
| `Documents/Projects/project-notes.txt` | No matching raw FILE record or inventory path | Not assessable | Not attempted | No recovered bytes; expected 133 bytes, manifest SHA-256 `838960d06f82442f85f7efa556a34642a3b0654a1a9506c31a389f4de62e4b6e` |
| `Archive/fragmented-test.bin` | No matching raw FILE record or inventory path | Not assessable | Not attempted | No recovered bytes; expected 262,144 bytes, manifest SHA-256 `ab082dde5f3d24b902315e8dfebf5bec217f4876059fce3f0611acec3e7ca809` |
| `Photos/photo-3.txt` | Record 49, deleted, resident unnamed DATA, 19 bytes | `not_applicable` | Previously recovered normally; not re-extracted in this nonresident-only validation | Exact prior SHA-256 match: `ecab875a6f631eb357705cdaa1e470cda266df8a02b53a8c04a8bc0b4bc1a602` |

For record 49, the FILE flags are `0x0`, sequence number `2`, and the
resident DATA content hash matches the manifest. It has no mapping pairs or
external clusters, so it is not a deleted nonresident case.

No target reached the condition required for nonresident extraction
(`FILE` present, complete unnamed nonresident DATA, valid mapping pairs, and
`allocation_status == "unallocated"`). Consequently, no recovery API call and
no output destination were created for either missing nonresident target.
No production defect was discovered, so no new regression tests were added
and no allocation-safety policy was changed.

## Synthetic deleted-file discovery pass

The existing deterministic synthetic NTFS image was used to validate a
separate discovery path. Its deleted nonresident records have FILE_NAME
metadata but no directory-index dependency. `NTFSVolume.discover_deleted_files`
walks the MFT, retains deleted records with nonzero sequence numbers, rejects
ambiguous or malformed DATA metadata, validates VCN continuity and physical
cluster bounds, and attaches the normal allocation assessment. It does not
override allocation policy or extract data itself.

The focused command was:

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_ntfs_recovery.py tests/test_synthetic_ntfs_image.py
python3 -m unittest -v \
  tests.test_synthetic_ntfs_image.SyntheticNTFSImageTests.test_deleted_discovery_is_independent_of_directory_indexes \
  tests.test_synthetic_ntfs_image.SyntheticNTFSImageTests.test_generated_image_is_reproducible_and_consumable \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_discovery_finds_unindexed_nonresident_file_and_recovers \
  tests.test_ntfs_recovery.NTFSRecoveryTests.test_deleted_recovery_conservatively_skips_uncertain_allocation
```

Result: `Ran 4 tests in 0.056s — OK`.

The synthetic image produced these deterministic results:

| Record | DATA mapping | Allocation | Normal recovery | Verification |
|---:|---|---|---|---|
| 12 (`deleted-free.txt`) | One nonresident run at LCN 320, VCN 0 | `unallocated` | Recovered | Output size and SHA-256 matched the generated manifest |
| 13 (`deleted-reused.bin`) | Two nonresident runs at LCNs 321 and 322, VCNs 0 and 1 | `mixed` | `skipped-allocation` | No output file created |

The test also includes a malformed incomplete mapping-pair record, which is
excluded by discovery. The successful recovery destination was created under
`/dev/shm`, separate from the temporary source image, so the existing source
filesystem-separation check remained active. No physical device or Seagate
source was accessed.
