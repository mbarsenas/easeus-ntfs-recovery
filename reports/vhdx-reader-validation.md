# Read-only VHDX reader validation

Implemented `VHDXReader` in `src/ntfs_recovery.py`. It is a seekable,
read-only source for `NTFSVolume` and supports dynamically expanding VHDX
payload states, zero/unallocated blocks, and partially present blocks through
the VHDX sector bitmap. It validates VHDX identifiers, CRC32C checksums,
header copies, region bounds, required metadata, virtual size, sector sizes,
block geometry, BAT bounds, payload offsets, and supported BAT states.

No external Python dependency was added. The source VHDX is never opened for
writing, mounted, repaired, or modified.

## Focused commands

```text
python3 -m py_compile src/ntfs_recovery.py tests/test_vhdx_reader.py
python3 -m unittest tests.test_vhdx_reader tests.test_synthetic_ntfs_image -v
```

Result:

```text
Ran 4 tests in 1.505s
OK
```

The synthetic tests cover valid metadata, full/zero/partial BAT states,
sector bitmap bits, cross-sector reads, virtual-end clamping, invalid
checksums, and invalid signatures.

## Supplied VHDX

Validation used bounded reads only:

```text
PYTHONPATH=. python3 - <<'PY'
from src.ntfs_recovery import VHDXReader, NTFSVolume, is_easeus_ntfs_boot_sector, validate_ntfs_candidate

path = "/mnt/c/Users/Mark/AppData/Local/Temp/ntfs-recovery-test.vhdx"
with VHDXReader(path) as source:
    assert source.virtual_size == 2147483648
    assert source.logical_sector_size == 512
    assert not is_easeus_ntfs_boot_sector(source.read_at(0, 512))
    offset = 0x01000000
    assert is_easeus_ntfs_boot_sector(source.read_at(offset, 512))
    with NTFSVolume(source, offset=offset) as volume:
        record0 = volume._record0()
        assert record0.number == 0
        assert record0.raw[:4] == b"FILE"
        candidate = validate_ntfs_candidate(source, offset)
        print(candidate.mft_record_readable, candidate.mft_runs_readable,
              candidate.backup_matches)
PY
```

The command printed:

```text
True True False
```

Observed results:

- Virtual capacity: `2,147,483,648` bytes.
- Logical sector size: `512` bytes.
- Virtual offset `0`: MBR, not NTFS.
- NTFS boot sector: virtual offset `0x01000000`.
- NTFS geometry: 512-byte sectors, 8 sectors/cluster, 4,161,407 total
  sectors, `$MFT` LCN `173392`, `$MFTMirr` LCN `2`.
- MFT record 0: readable; signature `FILE`; mapping pairs readable.
- NTFS-reported backup DBR offset: `0x7ffefc00`; its bytes do not pass the
  NTFS boot-sector predicate (`backup_matches=False`).
- Targeted inventory read 48 valid records from the discovered MFT region.

The existing NTFS engine can inspect the VHDX through `VHDXReader` once the
partition offset is supplied. It can parse boot geometry, MFT metadata, FILE
records, names, and data-run metadata. The current validation does not claim
deleted-file recovery, and the observed inventory contains duplicate-looking
extension/name records and paths that require further filesystem-specific
validation before selecting the named deleted targets. No physical disk or
`/dev/sdg` was accessed.

## Limitations

- The reader supports dynamic VHDX payload states and sector bitmaps, but not
  differencing/parent VHDX chains or encrypted/compressed containers.
- It does not infer partition offsets; callers must provide the NTFS offset.
- The supplied image's backup DBR is not valid at the NTFS-reported location.
- No deleted-file extraction was attempted.
