# Independent NTFS recovery implementation

This project is read-only and operates on a caller-supplied image or device
handle. It implements the recovery stages evidenced in the EaseUS DLL:
boot-sector/backup validation, MFT record traversal, FILE update-sequence
fixups, resident and nonresident attributes, signed NTFS data runs, sparse
streams, deleted-record enumeration, and raw FILE-record deep scanning.

The recovered DLL’s exported entry points are `EUCreateNTFSQuickSearcher` and
`EUCreateNTFSSearcher`. Ghidra evidence shows the quick path using a configurable
`fastsearch` setting, while the general path scans record-sized blocks, checks
for `FILE`, analyzes the boot record and directory records with
`INDEX_ALLOCATION`, and builds partition information from indexed records.
The implementation here is independent source code, not a binary wrapper or a
claim of source equivalence.

Run tests with:

```sh
python3 -m unittest discover -s tests -v
```

Example listing (including deleted records):

```sh
PYTHONPATH=. python3 -m src.ntfs_recovery image.dd --deleted
```

## Verified reliability boundary

Focused synthetic raw-image and VHDX validation currently verifies:

- NTFS boot geometry and explicit candidate validation.
- MFT record-0 mapping, fragmented MFT record reads, FILE/USA validation, and
  deleted-record discovery independent of directory indexes.
- Resident and nonresident unnamed DATA, fragmented and sparse mapping pairs,
  initialized-size zero filling, and multiple nonresident extents.
- `$Bitmap` coverage validation using the correct NTFS sector-to-cluster
  conversion, with conservative `allocated`, `unallocated`, `mixed`, and
  `unknown` outcomes.
- Default skipping of deleted files whose clusters are allocated, mixed, or
  unknown; no override is required for complete deleted resident DATA.
- Streaming extraction with short-read/gap detection, exclusive destination
  creation, source/destination separation, symlink rejection, pinned-source
  checks, collision handling, and output SHA-256 reporting.
- Read-only dynamic VHDX access through the internal `VHDXReader`.

Known limitations:

- The supplied Windows-created VHDX contains no raw FILE records for the
  original `project-notes.txt` or `fragmented-test.bin`; their contents are
  not claimed recoverable.
- `$ATTRIBUTE_LIST` and damaged directory indexes remain dependent on the
  metadata that survives in the source records.
- Output SHA-256 proves the bytes written to the destination, not the forensic
  provenance of bytes recovered from a deleted file.
- VHDX differencing/parent chains, encrypted containers, and physical-device
  validation are outside the synthetic test boundary.
