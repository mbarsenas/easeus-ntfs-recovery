# EaseUS NTFS search/recovery focused reconstruction

This report records the focused static pass over the existing Ghidra snapshot
and exported pseudocode. No new binary analysis was run and `/dev/sdg` was not
opened.

## Confirmed pipeline

```text
EUCreateNTFSSearcher 0x180001010
  -> FUN_18001d780 -> FUN_18001d7e0
  -> CNTFSSearchController (0x4a8-byte object)
  -> FUN_180021b70 (physical sector enumerator)
      -> FUN_1800201c0 (DBR/partition candidate)
          -> FUN_18001ffe0 (candidate geometry/bounds)
          -> FUN_18001fca0 (backup DBR duplicate test)
      -> FUN_1800217b0 (record fragment and FILE/metadata classifier)
          -> FUN_180018360/0x180018d00 (FILE USA validation/fixup)
          -> FUN_1800213b0 (directory INDEX_ALLOCATION handling)
              -> FUN_180021060 (partition info from directory index)
          -> FUN_1800215f0 (DBR/volume metadata path)
      -> FUN_1800205f0 (INDX record accumulation)
      -> FUN_1800381e0/FUN_1800389d0 (discovered-object managers)

EUCreateNTFSQuickSearcher 0x180001030
  -> FUN_18004bd00 -> FUN_18004bc60
  -> CNTFSQuickSearch (0x238-byte object)
  -> fast-search initialization at FUN_18001e410/FUN_180023fc0
```

The sector enumerator's decompilation shows storage-vtable reads, zero-sector
skipping, optional skip callbacks, 0x10-sector grouping, `INDEX`/`RSTR`
classification, and per-sector dispatch. The full search path is therefore a
physical discovery path; the quick path is a configured fast path rather than
the same class with a different display mode.

## Function/address map

| Address | Confirmed role |
|---|---|
| `0x180001010` | Full-search factory; constructs `CNTFSSearchController`. |
| `0x180001030` | Quick-search factory; constructs `CNTFSQuickSearch`. |
| `0x18001d7e0` | Full-search controller constructor and manager initialization. |
| `0x18004bc60` | Quick-search constructor; initializes quick-search vtables/state. |
| `0x18001e410` | Initialization; reads `Config.dat` `search/fastsearch`, selects quick setup for suitable storage. |
| `0x180023fc0` | Reads sector zero through the storage interface; validates it with `0x180016970`; creates a fast-search partition object. |
| `0x180016970` | Exact NTFS DBR predicate: OEM, sector/cluster constraints, zero legacy BPB fields, `55 AA`. |
| `0x180021b70` | Main physical-sector enumeration and dispatch loop. |
| `0x1800201c0` | Boot/DBR candidate creation, backup comparison, and candidate-list insertion. |
| `0x18001ffe0` | Candidate extent/geometry object construction and alignment to storage sector size. |
| `0x18001fca0` | `IsBackupDBR`; iterates prior candidates and marks a duplicate. |
| `0x18001fc30` | Backup comparison helper; compares candidate fields at `+0x38` and `+0x68`. |
| `0x1800217b0` | FILE-sized fragment assembly, USA fixup, metadata classification. |
| `0x180018aa0`, `0x180018c60`, `0x180018d00` | FILE record validation and update-sequence-array checks/fixup. |
| `0x1800213b0` | Directory record with `INDEX_ALLOCATION`; invokes partition-info builder. |
| `0x180021060` | Builds partition info from indexed directory records. |
| `0x1800205f0` | Accumulates and validates `INDX` records. |
| `0x18003db60`, `0x18003e110`, `0x18003df40` | INDX signature/bounds validation and USA fixup. |
| `0x180020f20` | `CountFilesandFoldersMatch` reference; counts/matches discovered partition objects. |

## Implemented changes

`src/ntfs_recovery.py` now includes:

* `is_easeus_ntfs_boot_sector`, mirroring `FUN_180016970` rather than only
  checking the OEM string.
* `NTFSCandidate`, including physical offset, volume extent, backup DBR status,
  and MFT readability status.
* `validate_ntfs_candidate`, which checks primary geometry, probes the standard
  last-sector backup DBR, compares geometry fields, opens the candidate as a
  read-only `NTFSVolume`, and verifies `$MFT` record 0 plus its mapping pairs.
* `discover_ntfs_candidates`, which validates only caller-supplied offsets and
  intentionally performs no implicit full-device scan.
* `NTFSVolume.inventory` and `write_inventory`, producing a path-oriented
  report from FILE_NAME, INDEX_ROOT, INDEX_ALLOCATION, allocation flags, and
  unnamed data streams. Output is caller-selected and separate from the source.
* Stronger total-sector, MFT/MFTMirr, record-size, and index-size validation.

## Behaviors still not confirmed or implemented

* The exact storage-interface sector stride and skip-callback policy in all
  quick/deep modes is not fully named; the call relationships are confirmed.
* The internal meanings of the candidate fields at `+0x38` and `+0x68` are
  confirmed as the duplicate-comparison inputs, but not their original C++
  member names.
* The Python implementation now follows resident `$ATTRIBUTE_LIST` entries
  into extension FILE records, but the EaseUS extension-record policy and its
  handling of malformed lists are not confirmed by the retained pseudocode.
* EaseUS-specific reconstruction heuristics for damaged directory indexes and
  its final partition scoring remain only partially recovered.
* The repository contains no surviving `ntfs_scan.py` process/output or known
  NTFS offset; the prior status report records that no candidate was established.

## Next engineering step

Run `discover_ntfs_candidates` against a short, caller-supplied list of
read-only physical offsets obtained from the existing Seagate scan/partition
metadata, then select the candidate with matching backup DBR and readable
record 0. Open that candidate with `NTFSVolume` and call `write_inventory` to a
different drive. If record 0 is valid but files are incomplete, implement
`$ATTRIBUTE_LIST` extension-record chaining before attempting bulk extraction.

## Focused physical-sector enumeration: `0x180021b70`

This section is based only on the retained Ghidra snapshot and exported
pseudocode. It does not establish runtime values supplied by the caller.

### Signature and confirmed data flow

The decompiler gives:

```c
uint64_t FUN_180021b70(
    Controller *self,       // param_1
    int64_t first_sector,   // param_2
    int64_t sector_count,   // param_3
    SkipBitmap *skip_map    // param_4, nullable
);
```

The first parameter is the `CNTFSSearchController` object: the function uses
`self+0x68` as the storage object, `self+0x70` as the scan buffer, and
`self+0x78` as the byte size of the retained overlap area. The last parameter
is nullable. Its first word is tested as an enable/presence value; when
enabled, `+0x18` supplies a bit-count and `0x18003cd80` tests the bit for the
current sector.

The return value is the constant integer `1` on the normal terminal path. No
failure return is visible in this function; read/parse outcomes are delegated
to the helper calls.

### Detailed pseudocode

```text
enumerate(self, first, count, skip):
    candidate_count = 0                 // DAT_180103fc0 = 0
    overlap_sectors = DAT_180105474    // initial value is not established

    storage.read(
        self.buffer + self.overlap_bytes,
        first,
        count
    )

    sector_bytes = storage.sector_size() // vtable + 0x18
    cursor = self.buffer + self.overlap_bytes
              - overlap_sectors * sector_bytes
    sector = first - overlap_sectors

    repeat:
        while sector < first + count:
            if *cursor != 0:
                break
            cursor += sector_bytes
            sector += 1

        if sector >= first + count:
            DAT_180105474 = 0
            retain_last_overlap(self, count) // 0x180021fa0
            return 1

        if skip != NULL and skip.enabled() and skip.bit_is_set(sector):
            if sector % skip.bit_count() == 0:
                sector += skip.bit_count()
                cursor += skip.bit_count() * sector_bytes
            else:
                sector += 1
                cursor += sector_bytes
            continue

        window_sectors = min(0x10, first + count - sector)
        window_bytes = window_sectors * sector_bytes

        if is_valid_rstr_record(cursor, window_bytes):
            classify_rstr(self, sector)
        else if not is_valid_ntfs_dbr(cursor):
            analyze_file_or_metadata(self, sector, cursor, window_bytes)
        else:
            if immortalize_gate():
                log("AnalyzeNTFSDBRSector", sector)
                construct_candidate(self, sector, cursor) // 0x1800201c0
                candidate_count += 1
                close_log()

        analyze_file_record_fragments(self, sector, cursor, window_bytes)
        notify_manager_1(self+0x1d8, sector, cursor)
        notify_manager_2(self+0x1e0, sector, cursor)
        cursor += sector_bytes
        sector += 1
```

The `RSTR` test is `0x180039120`: it rejects windows of at least `0x1000`
bytes, requires the `RSTR` signature and the UTF-16 `NTFS` marker at offset
`0x24`, then validates the update-sequence array. The DBR test is
`0x180016970`; it checks the `NTFS    ` OEM field, a nonzero 512-aligned
bytes-per-sector field, a permitted sectors-per-cluster byte, zeroed legacy
BPB fields, and the `55 AA` trailer.

### Chunking, overlap, and scan boundaries

| Item | Confirmed observation | Status |
|---|---|---|
| In-chunk increment | `cursor += sector_size`, `sector += 1` | Confirmed: every sector in the supplied range is considered sequentially. |
| Read call | Storage vtable `+0x08` receives `buffer + self+0x78`, `first`, `count` | Confirmed from decompilation; exact method name is unknown. |
| Sector size | Storage vtable `+0x18` | Confirmed source of value; numeric value is not hardcoded here. |
| Look-ahead window | `min(0x10, remaining)` sectors, passed as bytes to classifiers | Confirmed. `0x10` is 16 sectors. |
| Buffer overlap | `self+0x78` bytes are retained; `0x180021fa0` copies the final `self+0x78` bytes from `buffer + count*sector_size` to the buffer start | Confirmed. This preserves cross-chunk structures. |
| Starting sector | `param_2`, adjusted by an unknown global overlap value on entry | Caller-supplied; exact runtime value unknown. |
| Ending sector | Exclusive bound `param_2 + param_3` | Confirmed for one invocation. |
| Chunk size | `param_3` for one invocation; controller initialization allocates space based on a configured value at `self+0x60`, but the call that supplies `param_2/param_3` is not present as a direct exported reference | Numeric value and outer-pass policy unknown. |
| Multiple passes | No second pass or nonsequential jump is present inside this function. The nullable skip bitmap can jump by its bit-count, and the caller may invoke the function repeatedly. | Sequential inner pass confirmed; outer-pass behavior unknown. |
| Zero-sector filtering | `*cursor == 0` skips a sector before parsing | Confirmed. Only the first machine word is tested. |
| Bitmap filtering | Optional `skip` callback/bitmap can skip individual sectors or aligned bitmap blocks | Confirmed structurally; bitmap ownership/meaning is unknown. |
| Early exit | Stops when the supplied exclusive end is reached; retains overlap and returns `1` | Confirmed. No error return is visible. |

`0x18001e410` confirms that initialization obtains the storage sector size,
sets `self+0x78 = sector_size * 0x10`, and allocates
`self+0x60 * sector_size + self+0x78` bytes. The setter at `0x18001e3f0`
stores a caller-provided value at `self+0x60`. This establishes a 16-sector
overlap buffer, but does not establish the numeric outer chunk size or the
full-disk range.

### Relationship to candidate construction

```text
caller / controller virtual search method [direct caller not recovered]
  -> 0x180021b70(self, first_sector, sector_count, optional_skip_map)
      -> storage vtable +0x08: read one supplied sector range
      -> 0x180039120: RSTR/INDX-like record window test
           -> RSTR classification path
      -> 0x180016970: NTFS DBR predicate
           -> 0x1800201c0(self, current_sector, 512-byte DBR)
                -> 0x180016740 / 0x180016970: copy only valid DBR
                -> 0x180016860: DBR field at +0x28
                -> 0x18001ffe0: candidate geometry/extent object
                -> 0x18001fca0: compare against existing candidates
                     -> 0x18001fc30 compares candidate fields +0x38 and +0x68
                -> candidate-list insertion/release
      -> 0x1800217b0: FILE-record/metadata analysis over same window
      -> 0x1800381e0 and 0x1800389d0: discovered-object managers
      -> 0x180021fa0 at end: copy final 16-sector overlap
```

`0x1800201c0` constructs two related candidate forms. For a DBR-derived
length/extent value, it calls `0x18001ffe0` with mode `2`, runs the backup or
duplicate comparison, adjusts one extent by the DBR `+0x28` field when that
comparison succeeds, and inserts it into the list at `self+0x1f0`. It then
constructs the current-sector form with mode `1` and inserts it through the
controller's candidate collection at `self+0xd0`. The exact C++ meanings of
the candidate fields remain unknown.

`0x18001ffe0` rejects negative proposed starts and candidates with fewer than eight
storage sectors remaining. It clamps the extent to storage size minus the
candidate parameter, rounds it down to a whole storage sector, and stores the
resulting sector count in the candidate object. This is the confirmed local
boundary logic; it is not proof that the caller scans the entire physical
device.

### Confirmed constants and unknowns

| Constant/condition | Meaning established by disassembly |
|---|---|
| `0x10` | Maximum 16-sector look-ahead and retained overlap size in sectors. |
| `0x1000` | Maximum record-window byte length accepted by `0x180039120`. |
| `0x98` | Minimum byte length for the `RSTR` signature helper. |
| `0x58444e49` | Little-endian `INDX` signature used by the cached-window path. |
| `0x52545352` | `RSTR` signature. |
| `0x180016970` | NTFS DBR predicate; no partition-size check occurs there. |
| `self+0x60` | Caller-provided buffer/chunk-related count used during initialization; exact semantic name unknown. |
| `DAT_180105474` | Entry overlap adjustment; initial value is not established by the exported function set. |
| `param_2`, `param_3` | One invocation's start sector and exclusive range length, based on arithmetic and storage-read arguments. |
| Full-disk start/end and pass schedule | Not established by `0x180021b70` alone. |

### Implementation plan

The Python engine should add a separate physical-discovery iterator rather
than changing offset-based recovery:

1. Accept an explicit `(start_sector, sector_count, chunk_sectors)` supplied by
   the caller; do not infer a full-disk scan range.
2. Read each chunk into a buffer with a 16-sector overlap prefix/suffix,
   retaining the final 16 sectors between chunks.
3. Enumerate each sector sequentially, skip all-zero sectors, and optionally
   consult a caller-supplied skip bitmap.
4. Pass up to 16 sectors of look-ahead to the existing DBR/record classifiers.
5. On a validated DBR, call the existing candidate validation and geometry
   code, preserving the physical sector as the candidate origin.
6. Keep the scan range and chunk size explicit in the CLI so no accidental
   full-device scan is introduced.

The existing implementation deliberately validates only caller-supplied
offsets. The reverse engineering confirms the inner enumeration behavior but
does not provide a safe numeric start, end, or chunk size for the real disk.

## Focused MFT and directory reconstruction findings

This section is based on the existing exported pseudocode only. No new binary
analysis or runtime observation was performed.

### Confirmed call flow

```text
0x180021b70  physical sector enumerator
  -> 0x1800217b0  FILE-sized window classifier
       -> 0x180018360  FILE record wrapper
            -> 0x180018aa0  minimum-size/signature/attribute validation
                 -> 0x180018d00  USA validation and fixup
                 -> 0x180018970  attribute-record walk
       -> 0x1800213b0  directory record with index allocation
            -> 0x180040e80  INDEX_ROOT/INDEX_ALLOCATION extraction
            -> 0x180021060  indexed partition-object construction
       -> 0x1800205f0  INDX window accumulation
            -> 0x18003db60  INDX signature/bounds/USA validation
```

`0x180021b70` examines every nonzero sector in its supplied range. It passes
up to sixteen sectors of look-ahead to `0x1800217b0`. The classifier is
therefore a physical-sector discovery path, not a routine that is visibly
invoked with an MFT record number.

### MFT and MFTMirr LCN use

The DBR candidate constructor retains DBR-derived geometry fields in the
candidate object. In the examined path, `0x18001ffe0` stores the total-sector,
cluster-size, storage-sector-size, and a DBR field used later by the duplicate
comparison. The retained pseudocode does not show a subsequent read at the
standard DBR MFT LCN (`0x30`) or MFTMirr LCN (`0x38`), nor a comparison against
an MFTMirr FILE record.

What is confirmed is that EaseUS discovers FILE records by scanning physical
sectors and classifying FILE-sized windows. A direct DBR-MFT-LCN jump, MFT
mirror fallback, or use of the standard MFTMirr record to repair record 0 is
not established by these artifacts.

### FILE record size, signature, and USA behavior

`0x1800217b0` supplies a window of at least `0x400` bytes, increasing the
window to the storage sector size when that is larger. `0x180018aa0` rejects
windows below `0x400`, calls `0x18001d560` for the FILE/record-level initial
predicate, then calls `0x180018d00` and `0x180018970`.

The USA chain is:

```text
0x180018d00
  -> 0x180018c60  compare the USA sequence word with sector tails
  -> copy replacement words from the USA array into up to two sector tails
```

The decompiler shows a two-sector cap in these helpers (`local_10 < 2`) and a
minimum input size of `0x400`. The surrounding record path also treats the
record length field at record offset `+4` as the attribute-walk increment via
`0x18001c020`; malformed or zero-length records terminate or fail the walk.
The exact original FILE-record C++ type and whether other callers use larger
records are not recoverable from this focused path.

`0x180018360` stores either the original window or a copied/fixed buffer. If
validation fails, it clears the wrapper. If validation succeeds, the fixed
buffer is retained for downstream classification.

### Corrupt, unreadable, and deleted records

The visible classifier rejects short windows, invalid USA sequences, malformed
attribute lengths, and inconsistent attribute walks. `0x1800217b0` still
dispatches the window to the auxiliary managers after the main classification
result; its return value is used as a success/failure count by the enumerator.
No retry, MFTMirr substitution, or explicit deleted-record rejection is
visible in these functions.

`0x180018770` is the recovered FILE-header flag accessor for bit `0x1` at
record offset `0x16`, i.e. the NTFS in-use bit. `0x1800185b0` is the
corresponding directory-bit accessor (`0x2`). The visible caller
`0x1800170e0` invokes the in-use accessor, but its decompiled body discards the
returned value; the retained dispatch code does not show a branch that rejects
an otherwise structurally valid record solely because this bit is clear.
Therefore the existence of the in-use test is confirmed, but the final
deleted-record retention policy remains unknown.

### Attribute lists and extension records

The examined `0x180040e80` path locates attributes by type (`0x90` for
`INDEX_ROOT`, `0xa0` for `INDEX_ALLOCATION`) using `0x180018890`. The retained
call graph does not show a type `0x20` `$ATTRIBUTE_LIST` traversal that reads
extension FILE records and merges their attributes into a base record.

Therefore extension-record chaining is not confirmed for EaseUS from the
available artifacts. The current Python implementation does have explicit
`$ATTRIBUTE_LIST` parsing and sequence checks in `NTFSVolume.expand_attributes`;
that is an independent implementation feature, not a confirmed reproduction
of the DLL's behavior.

### `$I30`, `$INDEX_ALLOCATION`, and INDX processing

`0x1800213b0` is reached from `0x1800217b0` after the record classifier detects
the directory/index condition. It creates a temporary record-info object and
calls `0x180040e80`. That helper:

1. extracts the first resident `INDEX_ROOT` attribute (`0x90`);
2. extracts `INDEX_ALLOCATION` (`0xa0`) when present;
3. validates/parses the associated index metadata through
   `0x18001d150`/`0x18001d250`; and
4. returns the object to `0x180021060`, which maps its stored records back to
   physical locations and inserts accepted objects into the controller's
   candidate collection.

Separately, `0x1800205f0` recognizes an `INDX` window through
`0x18003db60`. `0x18003e110` requires the `INDX` signature, checks the index
length and entry bounds, validates the USA count/sector relationship, and
`0x18003df40` applies the USA replacement words. The parser then accumulates
the validated index object and deduplicates/associates it through
`0x180020420`.

The exact on-disk `$I30` key extraction, collation order, child FILE-reference
field, and treatment of the index end marker are not recoverable from the
available decompilation because those operations are inside helpers whose
types and bodies are not named in this export.

### Parent references, sequence numbers, and paths

The retained EaseUS snippets show index/object association and physical
sector/cluster mapping, but do not show a confirmed FILE_NAME parent-reference
walk, parent sequence-number comparison, or root-anchored path builder. Thus
the following are not confirmed DLL behavior from this pass:

* validating the high 16 bits of a FILE reference against the target FILE
  record sequence number;
* selecting among multiple FILE_NAME namespaces;
* rejecting stale directory-index references after record reuse;
* walking parent references to reconstruct a full original path.

The metadata required for such a reconstruction is nevertheless clear from
the format and from the independent Python implementation: record number and
sequence, FILE in-use/directory flags, resident FILE_NAME attributes with
parent reference and parent sequence, and valid `$I30`/`INDEX_ALLOCATION`
entries. Missing parent records, damaged indexes, or unresolved extension
records prevent a unique path.

### Comparison with `src/ntfs_recovery.py`

| Area | EaseUS behavior confirmed here | Current Python implementation |
|---|---|---|
| MFT location | Physical FILE-window discovery is confirmed; DBR-LCN jump is not | Reads record 0 from DBR MFT LCN, then follows `$MFT` data runs |
| Record size | `0x400` minimum in this path; record header length drives attribute walk | Uses BPB-derived record size and validates it more strictly |
| USA | Checks sequence words and fixes sector tails before parsing | `apply_fixup` validates every record sector and restores tails |
| Corruption | Rejects malformed/short/USA-invalid windows; retry policy unknown | Skips unreadable MFT records and invalid index blocks |
| Deleted records | Explicit policy not visible | Optional through `include_deleted` and FILE flags |
| `$ATTRIBUTE_LIST` | Not confirmed in retained DLL path | Explicit extension-record chaining with sequence checks |
| `$I30`/INDX | Index validation and object accumulation confirmed | Parses `INDEX_ROOT`, `$INDEX_ALLOCATION`, `INDX`, and `$BITMAP` |
| Parent paths | Parent walk not visible in this pass | Uses FILE_NAME parent references and sequence validation |

The Python implementation should not claim exact EaseUS parity for parent-path
selection, deleted-record policy, or attribute-list behavior until the hidden
helpers and their callers are recovered.

## Physical-sector to FILE-record discovery

This section traces the existing exported bodies for `0x180021b70`,
`0x1800217b0`, `0x180018aa0`, `0x180018d00`, `0x1800213b0`, and
`0x1800205f0`. It is static-only; no new analysis or runtime observation was
performed.

### Exact discovery flow

```text
0x180021b70(self, first_sector, sector_count, skip_map)
  -> storage.read(buffer + overlap, first_sector, sector_count)
  -> cursor starts at first_sector - overlap_sectors
  -> for each physical storage sector:
       skip if first machine word is zero
       optionally skip bitmap-selected sectors/blocks
       window = min(16, sectors_remaining) * storage_sector_size
       if DBR predicate succeeds:
           0x1800201c0(self, sector, cursor)
       else if RSTR predicate succeeds:
           0x180038cf0(...)
       else:
           0x1800205f0(self, sector, cursor, window)
       0x1800217b0(self, sector, cursor, window)
       notify auxiliary managers
       cursor += storage_sector_size; sector += 1

0x1800217b0
  -> 0x180018360(window, 0x400-or-sector-size, copy_mode=0)
       -> 0x180018aa0
            -> 0x18001d560: FILE header/size predicate
            -> 0x180018d00: USA tail validation and fixup
            -> 0x180018970: attribute-record walk
  -> 0x18003ab00(FILE wrapper, physical sector)
  -> if wrapper valid:
       classify $MFT/$MFTMirr/$Bitmap and index-bearing records
       -> 0x1800213b0 for directory/index allocation records
       -> 0x1800215f0 for other NTFS metadata
```

### FILE signature and record-window rules

`0x180021b70` does not search for `FILE` at arbitrary byte offsets. It tests
the current storage-sector pointer, and the next iteration tests the next
storage sector. The only cross-sector special case is the retained 512-byte
fragment: when a FILE-looking window is shorter than `0x400`,
`0x1800217b0` saves the sector and combines it with the immediately following
sector if the physical sector numbers are consecutive.

`0x18001d560` confirms the following predicate:

```text
header[0:4] == "FILE"
USA_count_at_0x06 < 0x11
record_size_field_at_0x1c < 0x1001
record_size_field_at_0x1c is divisible by 0x400
record_size_field / 0x200 is compatible with USA_count - 1
header_size_field_at_0x04 is within the accepted upper bounds
```

The last two checks are expressed through decompiler field arithmetic and the
returned value is used only for its low byte by `0x180018aa0`; the original
member names are unavailable. The surrounding path always supplies at least
`0x400` bytes and then calls the attribute walk. A storage sector larger than
`0x400` increases the wrapper input size, but the explicit fixup/classification
call in `0x1800217b0` still uses `0x400`.

No cluster-boundary or MFT-LCN alignment check is visible. The confirmed
alignment is storage-sector stepping, with FILE records expected to be
recognized at those sector starts. Any stronger 1-KiB/cluster alignment is
unconfirmed.

### USA and attribute validation

`0x180018aa0` rejects windows below `0x400`, rejects the FILE predicate, and
rejects an invalid attribute walk. `0x180018d00` first calls `0x180018c60`,
which compares the USA sequence word against sector tails, then copies USA
replacement words into at most two sector tails. `0x180018970` walks attributes
using the record length at each attribute header; it rejects malformed lengths
and specifically validates an attribute type `0x30` through its own helper.

Thus a FILE signature alone is insufficient: the window must pass FILE header,
USA, and attribute-record validation before it reaches the object managers.

### Association with candidates

The FILE path is not gated by a previously validated DBR candidate. The
enumerator calls `0x1800217b0` for every nonzero sector window regardless of
whether `0x1800201c0` created a candidate at that sector.

`0x18003ab00` receives both the physical sector number and the validated FILE
wrapper. It maintains a separate discovered-object manager and performs
position/continuation checks before dispatching the record. The visible special
classification calls are:

```text
0x18001bbc0 -> look for "$MFT"
0x18001bc20 -> look for "$MFTMirr"
0x18001bce0 -> look for "$Bitmap"
```

For ordinary validated records, the manager inserts or updates a discovered
object associated with the physical sector. The exact C++ object type and the
final conversion from this object to a user-visible partition are not present
in the exported pseudocode.

`0x18003ae70` also compares the record-derived value from `0x18001b990` with
`(physical_sector - manager_base) / 2` when an existing stream/object is being
continued. This establishes a record-position continuity check. The exact
meaning of the division-by-two unit and the record-derived field is inferred
from arithmetic, not a recovered type definition.

### Candidate dependence and incomplete candidates

`0x1800201c0` is independently called only when the DBR predicate succeeds;
it builds primary and backup-derived candidate objects and inserts them into
candidate collections. The FILE classifier runs even when no candidate exists,
when the candidate is incomplete, and when the FILE sector is not itself a
DBR.

The available code shows no explicit requirement that a FILE record fall within
an already accepted candidate extent. It instead preserves the record in the
separate discovered-object managers. Whether a later controller stage merges
such objects into a partition, discards them, or presents them as an
independent result is not confirmed.

### Duplicate and continuation handling

There are two distinct mechanisms:

1. DBR candidates use `0x18001fca0`/`0x18001fc30` and the candidate duplicate
   fields documented earlier in this report.
2. FILE records use `0x18003ab00` plus manager helpers. The visible logic
   rejects/continues records based on manager state and the record-position
   comparison above; the exact object identity key is hidden in
   `0x18003ae30`, `0x1800402a0`, and related container helpers.

No confirmed FILE duplicate key based on record number, sequence number, or
physical offset is available from the retained decompilation.

### Can this recover MFT records without a DBR?

Structurally, yes: the enumerator can recognize and pass FILE windows to
`0x1800217b0` without a successful DBR candidate or a usable DBR MFT LCN. It
also explicitly recognizes `$MFT` by name through `0x18001bbc0`.

What is not confirmed is whether the later manager/controller will construct a
complete volume from those records without candidate geometry. The scan path
can discover FILE/$MFT evidence independently; complete MFT extent mapping,
directory reconstruction, and file recovery still require enough volume
geometry and data-run metadata.

### Comparison with the Python scanner

The existing Python implementation is offset-driven: `NTFSVolume` reads the
DBR at a caller-supplied offset, obtains MFT geometry, follows `$MFT` data
runs, and iterates record numbers. It does not currently reproduce this
physical-sector discovery loop or its 16-sector look-ahead/overlap behavior.

It is stronger after a candidate is known: it applies USA fixups, validates
attributes, handles sparse/fragmented runs, follows `$ATTRIBUTE_LIST`, and
validates FILE-reference sequences during directory reconstruction. It does
not yet reproduce EaseUS's independent FILE discovery, special `$MFT`/
`$MFTMirr`/`$Bitmap` object managers, or hidden continuation/deduplication
logic.

### Implementation recommendation

Do not replace the current offset-driven recovery path. If physical discovery
is added later, implement it as an explicit caller-bounded iterator:

1. read caller-supplied sector ranges only;
2. preserve the confirmed 16-sector overlap and storage-sector stepping;
3. skip zero sectors and optionally apply a caller-owned skip bitmap;
4. require the FILE predicate, USA fixup, and attribute walk before emitting a
   record observation;
5. retain observations separately from validated NTFS candidates; and
6. merge them only when geometry, MFT runs, and record identity can be
   independently validated.

The numeric full-disk range, outer pass schedule, exact FILE duplicate key,
and final candidate-to-record merge policy remain unconfirmed.

## Partition-independent MFT-region analysis

`src/ntfs_recovery.py` now provides:

```python
iter_raw_file_records(source, start_sector, sector_count,
                      storage_sector_size=512, *, chunk_sectors=16)
analyze_mft_regions(observations)
```

`iter_raw_file_records` yields validated `RawFileObservation` objects without
constructing `NTFSVolume`. The new `MFTRegionAnalyzer` consumes those objects
incrementally and retains only compact `MFTRegionObservation` metadata, not
the full raw record buffers. `finish()` returns `MFTRegionAnalysis`, containing
multi-observation region hypotheses, isolated observations, duplicate counts,
conflicting observations, and nonvalidated inputs.

Regions are formed only when at least two validated observations share a
record-size hypothesis and the same physical boundary residue. Equal
record-size spacing is reported as `contiguous`; compatible observations with
larger spacing are reported as `fragmented` and retain the observed deltas.
`$MFT`, `$MFTMirr`, and `$Bitmap` names are evidence strings only. No arbitrary
confidence score is assigned, and a single FILE record remains isolated.

The analyzer never derives an MFT record number from physical offset. Every
candidate remains `unvalidated` until independent evidence supplies the volume
start/boundary, MFT record-number origin, `$MFT` mapping pairs, and a usable
`$MFTMirr` comparison. `$Bitmap` allocation evidence and consistent record
sequence/reference checks are additional promotion evidence. Without those
inputs, a region is only a structured discovery hypothesis and must not be
used for full partition recovery.

## Focused candidate construction: `0x1800201c0`

### Exact control flow

`0x1800201c0(self, current_sector, sector_ptr)` is reached only after the
enumerator's NTFS DBR predicate succeeds. It does not independently read the
source device or search for another boot sector.

```text
zero a local 0x200-byte DBR buffer
if 0x180016740(local_dbr, sector_ptr) == false:
    release/return

total_sectors = 0x180016860(local_dbr)       // DBR +0x28, 8 bytes

backup_form = 0x18001ffe0(
    self,
    local_dbr,
    current_sector - total_sectors,
    mode=2
)

if backup_form != NULL:
    if 0x18001fca0(self, backup_form) != 0:
        // A previously seen candidate matches this form, or its flags mark it.
        backup_form.start_sector -= total_sectors
        insert(self + 0x1f0, backup_form, flags=2)
        release backup_form
        return

    adjust_existing_zero_length_candidates(self, backup_form)
    insert(self + 0xd0, backup_form)

primary_form = 0x18001ffe0(
    self,
    local_dbr,
    current_sector,
    mode=1
)
if primary_form != NULL:
    insert(self + 0xd0, primary_form)
return
```

The decompiler's `FUN_180024b20` wrapper resolves insertion into the ordered
candidate collection at `self+0xd0`; its tree/container implementation is
generic STL-like code. The important observable behavior is that the mode-2
form is also retained in the `self+0x1f0` collection when
`0x18001fca0` reports a match, while both the unmatched mode-2 form and the
current-sector mode-1 form are inserted through the `self+0xd0` collection
path. Before inserting an unmatched mode-2 form, `0x18001fe60` propagates its
nonzero extent into existing `self+0xd0` candidates whose length field is
still zero.

### DBR predicate: `0x180016970`

The predicate copies 0x200 bytes and examines these boot-sector positions:

| Boot offset | Check | Status |
|---:|---|---|
| `0x03..0x0A` | Case-insensitive comparison with `NTFS    ` | Required. |
| `0x0B..0x0C` | Unsigned 16-bit value is nonzero and divisible by `0x200` | Required. This is bytes per sector. |
| `0x0D` | One of `1,2,4,8,0x10,0x20,0x40,0x80,0x100` | Required. This is sectors per cluster. |
| `0x0E..0x0F` | Must equal zero | Required. |
| `0x10..0x14` | All five bytes must equal zero | Required. |
| `0x15` | Not examined by the recovered predicate | Unknown/unvalidated. |
| `0x16..0x17` | Both bytes must equal zero | Required. |
| `0x20..0x23` | All four bytes must equal zero | Required. |
| `0x1FE..0x1FF` | Bytes `55 AA` | Required. |

The predicate does not validate the DBR's total-sector field, MFT LCN,
MFTMirr LCN, record size, index size, update-sequence array, or a readable
FILE record. Those checks occur later or outside this function. It also does
not check the BPB fields at `0x18..0x1F` in the recovered pseudocode.

The predicate returns the low byte of its result to callers. For the accepted
case that low byte is `1`; nonzero non-boolean values are possible in some
malformed branches, so callers use a nonzero test rather than requiring the
full return value to equal one.

### Geometry extraction and clamping: `0x18001ffe0`

For a DBR and a proposed sector origin `candidate_start`:

```text
if candidate_start < 0:
    reject

total = uint64(DBR[0x28:0x30])
available = storage_size_sectors() - candidate_start
extent = min(total, available)
if extent < 8:
    reject

candidate = new 0xd0-byte CSearchedNTFSPartitionInfo(storage_sector_size)
candidate.mode_or_status = mode
candidate.type = 3
candidate.sectors_per_cluster = DBR[0x0D]
candidate.start_sector = candidate_start
candidate.mftmirr_lcn = uint64(DBR[0x48:0x50])
candidate.length_bytes = floor(extent, storage_sector_size)
candidate.sector_count = candidate.length_bytes / storage_sector_size
return candidate
```

The storage size is obtained through the storage vtable at `+0x10`; the
storage sector size comes from vtable slot `+0x18`. The eight-sector minimum is
applied after clamping. A negative start is rejected. There is no explicit
check that `candidate_start + total` fits before clamping; the available-size
clamp handles that case.

For the mode-2 form, `candidate_start = current_sector - DBR.total_sectors`.
Thus a DBR found at the end of a volume can yield the inferred volume start.
For the mode-1 form, `candidate_start = current_sector`, treating the DBR as
the primary volume origin. This is how backup DBRs are located in this path:
the physical enumerator encounters them at their actual sector; the code does
not independently probe a calculated last sector.

### Duplicate and backup comparison: `0x18001fca0`

`0x18001fca0` iterates the existing candidate collection at `self+0xd0`.
For each candidate it calls `0x18001fc30(existing, proposed)`, which returns
true only when both of these 64-bit fields match:

```text
existing + 0x38 == proposed + 0x38   // clamped length in bytes
existing + 0x68 == proposed + 0x68   // DBR[0x48], MFTMirr LCN
```

It also treats a candidate whose flags at `+0x74` already contain bit 0 as a
match, then sets bit 1 through `0x180040770(candidate, 2)`. Therefore the
confirmed duplicate criterion is the pair `(length_bytes, MFTMirr_LCN)` or
the candidate's existing bit-0 state. The physical start sector is not part
of `0x18001fc30`'s equality test. The original semantic names of these flags
are unknown.

### Retained candidate metadata

The object initialized by `0x180040d70` is a `0xd0`-byte
`CSearchedNTFSPartitionInfo`. Confirmed fields populated by this path are:

| Candidate offset | Value | Confidence |
|---:|---|---|
| `+0x08` | Type set to `3` by `0x18001ffe0` | Confirmed value; semantic name unknown. |
| `+0x0C` | DBR byte `0x0D` (sectors per cluster) | Confirmed. |
| `+0x10` | Proposed physical start sector | Confirmed. |
| `+0x30` | Storage sector size from constructor | Confirmed. |
| `+0x38` | Clamped extent length in bytes | Confirmed. |
| `+0x68` | DBR field `0x48..0x4F` (MFTMirr LCN position) | Confirmed source field; semantic use inferred from NTFS layout. |
| `+0x74` | Mode/status argument (`1` primary form or `2` backup form) | Confirmed value; semantic name unknown. |
| `+0x80` | Clamped extent in storage sectors | Confirmed. |

The constructor initializes several later fields (`+0x80` onward) to `-1` or
zero before these assignments. No MFT LCN from DBR offset `0x40` is copied by
`0x1800201c0` or `0x18001ffe0`. The candidate object therefore retains the
MFTMirr LCN, not a validated MFT location, at this stage.

### What is and is not validated here

Confirmed at candidate insertion:

* NTFS OEM signature and selected BPB invariants.
* Bytes-per-sector alignment and permitted sectors-per-cluster value.
* DBR total-sector field is used to infer a backup-derived start.
* Candidate start is nonnegative.
* Candidate extent is clamped to the storage boundary and aligned to the
  physical storage sector size.
* Candidate extent must be at least eight storage sectors.
* MFTMirr LCN is retained for comparison.
* Duplicate/backup status is tracked through candidate fields and flags.

Not established or not performed by this path:

* No direct validation of DBR offset `0x40` (MFT LCN).
* No FILE record 0 read or USA fixup.
* No MFTMirr record read.
* No comparison of primary and backup DBR bytes or full geometry fields.
* No validation of record size, index size, cluster count, or data runs.
* No proof that the mode-2 candidate is always a valid backup DBR rather than
  any DBR encountered at a sector whose total-sector arithmetic produces a
  plausible origin.

This narrows the Python implementation task: retain the existing strict
candidate validation for actual recovery, but add an optional EaseUS-compatible
discovery mode that reproduces the DBR predicate, the two proposed origins,
the eight-sector/clamped extent rule, and the `(length_bytes, MFTMirr_LCN)`
duplicate key. It must still perform our stronger record-0/MFT validation
before treating a candidate as recoverable.

## FILE evidence to partition-candidate association

This section traces the retained bodies for `0x18003ab00`, `0x1800201c0`,
`0x1800213b0`, `0x1800215f0`, `0x18001ed70`, and their visible container
helpers. It establishes only association mechanics visible in the DLL; hidden
C++ type names and external UI behavior remain unknown.

### Confirmed call flow

```text
0x180021b70
  -> 0x1800217b0(FILE window)
       -> 0x18003ab00(FILE wrapper, physical sector)
            -> FILE managers at self+0x1d8/0x1e0/0x1e8
            -> "$MFT" / "$MFTMirr" / "$Bitmap" classification
       -> 0x1800213b0 for index-bearing FILE records
            -> 0x180021060 and candidate collection self+0xd0
       -> 0x1800215f0 for other metadata

0x1800201c0(DBR, physical sector)
  -> primary/backup candidate construction
  -> self+0xd0 primary collection
  -> self+0x1f0 backup/duplicate collection

0x18001ed70 EndSearch
  -> iterates self+0xd0
  -> updates metadata managers and candidate fields
  -> 0x180023700 final candidate traversal
```

### FILE evidence storage and system-file association

`0x18003ab00` receives a validated FILE wrapper and physical sector from the
FILE classifier. It performs manager state/continuation checks through
`0x18003aa90`, `0x18003ae70`, and `0x18003ade0`, then dispatches evidence to
manager fields at `self+0x1d8`, `self+0x1e0`, and `self+0x1e8`.

The special-name tests are direct and confirmed:

```text
0x18001bbc0 -> "$MFT"
0x18001bc20 -> "$MFTMirr"
0x18001bce0 -> "$Bitmap"
```

These names select different metadata paths, but the exact object identity
key is not recovered. `0x18003ae30` exposes only a manager-base distance test;
the remaining identity logic is inside helpers such as `0x1800402a0`.

### Candidate collections

`self+0xd0` is the primary ordered candidate collection. `0x180024b20` is the
common ordered-container insertion wrapper, and `0x18001fca0` iterates this
collection for the confirmed DBR duplicate comparison.

`self+0x1f0` is an auxiliary backup/duplicate collection. In
`0x1800201c0`, a backup-derived candidate matching `0x18001fca0` has its
extent adjusted and is inserted into `self+0x1f0` through `0x180036580` with
flags `(clear=0, set=2)`. A nonmatching backup candidate is inserted into
`self+0xd0` after `0x18001fe60` updates zero-length entries; the primary form
is then also inserted into `self+0xd0`.

`0x180036580` enumerates matching auxiliary objects and updates their flags.
Its ordering key is hidden in STL/container helpers, but the update-versus-
insert distinction is confirmed.

### Candidate updates and merges

Confirmed update triggers are:

* DBR duplicate comparison in `0x18001fca0`/`0x18001fc30`;
* zero-length extent repair in `0x18001fe60`;
* backup/duplicate flag updates through `0x180036580`;
* FILE-manager continuation checks in `0x18003ae70`;
* end-of-search scoring and field updates in `0x18001eb50`.

`0x18001eb50` computes a bounded candidate score from object flags and fields
at candidate offsets `+0x88`, `+0x90`, and `+0x98`. The weights are visible,
but those fields' semantic names are not. This is scoring, not proof of a
valid NTFS volume.

`0x180020b40` is another visible association helper: it obtains physical
ranges from metadata, searches `self+0xd0`, and increments a candidate field
at `+0x28`. Its direct caller is not present in the exported references, so
its invocation stage is unknown.

### Can FILE evidence create or reject a candidate?

Ordinary FILE records do not visibly create candidates. Candidate creation is
in `0x1800201c0`, reached from the DBR branch of `0x180021b70`, not from
`0x18003ab00` or its FILE managers.

FILE evidence can update manager state and later contribute to candidate
fields/scoring. The visible code does not show arbitrary FILE records
expanding a candidate extent or rejecting it. Extent changes shown here come
from DBR total-sector arithmetic and duplicate/zero-length handling.

Directory/index records are the closest FILE-driven association: 
`0x1800213b0` calls `0x180021060`, which constructs index-related objects and
inserts accepted objects into `self+0xd0`. This is an indexed metadata path,
not proof that arbitrary FILE records create partitions.

### Final partition-candidate boundary

`0x18001ed70` is the strongest confirmed finalization point. It is labelled
`EndSearch`, iterates `self+0xd0`, invokes the FILE/index/metadata managers,
calls `0x18001eb50`, and removes or retains objects based on count and
metadata conditions. It then calls `0x180023700`, which traverses remaining
primary candidates and passes each to `0x180024800`.

The analyzed DLL does not expose a clear UI/display call or a named
`LostPartition` constructor after `0x180023700`. Therefore the exact point at
which a retained candidate becomes the displayed lost partition is not
confirmed. `0x18001ed70`/`0x180023700` is the last confirmed internal
candidate-finalization boundary.

### Confirmed rules and unknowns

Confirmed association inputs are physical sector position, DBR-derived
candidate geometry/extent, candidate collection membership, FILE-manager
state, system-file names, and metadata-derived range counts. No confirmed
association key combining FILE record number, MFT LCN, and volume start is
visible.

Unknowns include ordinary FILE-object identity, hidden manager merge behavior,
the meanings of candidate fields `+0x88`, `+0x90`, and `+0x98`, STL ordering
keys, and the external handoff that labels a retained object as a displayed
lost partition. These must not be reproduced as guessed rules.

## NTFS candidate evidence reconciliation

`src/ntfs_recovery.py` now provides `NTFSCandidateReconciler` and compact
evidence types:

```python
reconciler = NTFSCandidateReconciler()
reconciler.add_candidate(candidate)
reconciler.add_raw_observation(raw_observation)
reconciler.add_mft_region(region)
reconciler.add_directory_evidence(index_evidence)
report = reconciler.finalize()
```

The reconciler keeps DBR candidates, raw FILE summaries, MFT-region
hypotheses, and directory/index evidence separate. It retains only compact
metadata for raw FILE observations, not their record buffers.

Established association rules are intentionally narrow:

* An MFT region associates with a DBR candidate only when its start exactly
  equals `candidate.offset + geometry.mft_lcn * geometry.cluster_size`.
* Its record-size hypothesis must match `geometry.record_size`; otherwise the
  report contains contradictory evidence.
* Directory/index evidence associates only when it explicitly supplies the
  same `volume_offset` as the DBR candidate.
* Physical proximity, `$MFT`/`$MFTMirr` names, and matching names alone do not
  establish association.
* Ordinary FILE evidence never creates a partition candidate.

`finalize()` returns ranked `CandidateEvidenceReport` objects with an ordinal
rank and the exact supporting facts used for ordering. It also returns
contradictions, provenance, unresolved fields, and all unassociated evidence.
The result is an explainable evidence report, not a recovery-readiness claim;
partition boundaries, MFT record-number origin, MFTMirr agreement, and bitmap
state remain unresolved unless independently supplied.

## Nonresident data-run and fragmented-file recovery

This section is based only on the existing Ghidra decompilation. No device was
accessed and no new binary analysis was performed.

### Confirmed call flow

The clearest recovered data path is:

```text
record window
  -> 0x180049660
       -> 0x180018360 / 0x180049460
       -> stream/attribute object
  -> 0x180016d30
       -> 0x1800177b0
            -> 0x180018aa0
            -> 0x180018d00 (USA fixup)
            -> 0x180018890 (attribute lookup)
            -> 0x1800172d0 / 0x1800173f0 (per-attribute setup)
  -> 0x180016f50
       -> 0x180018aa0 / 0x180018d00
       -> 0x180016dd0 (fragment/sector dispatch)
  -> 0x18004a4f0
       -> data/read object and output-side consumers
```

`0x18004bd60`, `0x1800370d0`, and `0x180043850` all use this pattern. They
process a bounded record/window, reject a failed record or stream construction,
construct a fragment-aware object, then pass it to `0x18004a4f0`. The callers
also pass a unit size derived from the storage-reader virtual method at vtable
offset `+0x18`; this is used to convert byte positions to storage units.

`0x180022610` is a closely related output path. After creating the same read
object it attaches the object to an output manager (`0x180048d70`,
`0x180048550`, `0x180048850`, `0x1800485d0`, and `0x180048590`). The exact UI
or final-file naming layer is outside the confirmed data-run path.

### Mapping-pairs decoder

`0x1800198f0` is the confirmed mapping-pairs decoder. For each nonzero mapping
pair header it derives a run-length field width from the low nibble and an LCN
delta field width from the high nibble. It reads the run length as an unsigned
little-endian value, reads the LCN field as a signed little-endian value, and
maintains cumulative LCN and VCN state. Each decoded entry stores:

```text
entry.lcn_or_sparse
entry.vcn_start
entry.cluster_length
```

The decoder advances VCN by the run length and advances LCN by the signed
delta. A zero-width LCN field is represented internally by LCN `-1`, which is
the DLL's sparse-run marker. The mapping list terminates at a zero header.

The sign-extension branches explicitly cover one through seven-byte delta
fields. The decompiler leaves the assignment of the high-nibble width in a
temporary that is shown as zero in one part of the pseudocode; the surrounding
header-width validation in `0x180019500` and the subsequent signed-width
branches establish the intended low/high-nibble mapping, but the exact compiler
temporary assignment should not be treated as byte-for-byte source.

`0x180019500` validates the list before `0x1800198f0` consumes it: both nibble
widths are bounded by four in the validator's visible arithmetic, each pair
must fit within the supplied attribute value, and a zero header ends the list.
`0x1800195f0` copies decoded entries for later use. `0x180019c80` decodes a
list and adds a caller-supplied physical/logical base to every entry's stored
position, confirming that decoded extents can be rebased when an attribute
fragment is not the first extent.

### Record and attribute validation before data reads

`0x180018aa0` rejects buffers shorter than `0x400`, checks the record-level
header predicate, applies `0x180018d00`, and requires `0x180018970` to accept
the attribute layout. `0x180018d00` calls the lower-level USA check
`0x180018c60`; on success it restores the protected end-of-sector words for
up to two visible sectors. `0x180018b80` performs the corresponding broader
fixup loop. Thus a damaged FILE buffer normally fails before the data-run
reader is constructed.

`0x180018890` walks attributes from the record's attribute offset, stops at the
end marker or an invalid length, and selects an attribute by type and ordinal.
The data path uses type `0x80` through `0x180017f00`; the same enumeration also
permits multiple DATA attributes/extents to be processed in order.

### Fragmented-file reconstruction pseudocode

The confirmed behavior can be summarized as:

```text
for each bounded FILE/attribute window:
    if record size < 0x400 or record/USA/attribute validation fails:
        reject this window

    for each DATA attribute selected from the record:
        if resident:
            expose the resident value directly
        else:
            validate mapping-pair bytes
            decode (length, signed_delta) pairs
            vcn = attribute_lowest_vcn
            lcn = 0
            for pair in pairs:
                if pair has no LCN field:
                    add sparse extent(vcn, pair.length)
                else:
                    lcn += signed_delta
                    add physical extent(vcn, lcn, pair.length)
                vcn += pair.length

            combine/rebase the resulting extents into a logical stream object
            bound reads by the stream size maintained by the attribute object
            pass the stream object to the storage/output consumer
```

The physical read object is built incrementally. `0x180016f50` copies and
validates each input record, applies USA fixups, obtains the reader unit size,
and calls `0x180016dd0` with a unit count. `0x18004a4f0` then creates the
consumer object only if the stream object is valid. This confirms fragmented
reads are not implemented as one contiguous disk read.

`0x180041840` separately confirms the logical-to-physical conversion pattern
used by the DLL's extent objects: a logical position is divided by the unit
size, mapped through a base/extent lookup, and the remainder is preserved. It
rejects a result that cannot be represented as an integral unit position.

### Sizes, sparse data, and multiple extents

The stream object records at least a logical size and initialized/attribute
metadata. `0x18004a060` iterates type `0x80` attributes, obtains size values,
and for nonresident attributes constructs the physical extent collection. It
also clamps a derived size to an existing stream size when the latter is
already present, while preserving a nonzero derived size if the existing value
is zero. This is consistent with using the logical file size as the read limit;
the exact distinction between NTFS `data_size`, `initialized_size`, and
`allocated_size` is not named in the decompilation and is therefore not
confirmed.

Sparse extents are confirmed by the `-1` LCN marker in `0x1800198f0` and by
the extent/object consumers accepting an extent without a physical LCN. The
snapshot does not establish whether the output layer materializes sparse
regions as zero bytes, seeks over them, or preserves sparseness.

Multiple nonresident extents are supported at the object level: the attribute
enumeration in `0x18004a060` repeats until no type `0x80` attribute remains,
and `0x1800172d0`/`0x1800173f0` process the resulting collections. The exact
ordering and conflict rule for overlapping VCN ranges is not visible.

### Compression, damaged records, deleted files, and ADS

The attribute flags are copied into the internal stream object by
`0x180049710`; visible bits include `1`, `2`, `4`, `0x20`, and `0x400`.
`0x18004a060` also propagates internal flags `0x800` and `0x40`, and
`0x180043850` branches on a stream-object `0x400` flag. These observations
confirm that flagged streams receive special handling, but the snapshot does
not identify that handling as NTFS compression decompression, encryption, or
another policy. Compression support is therefore unknown, not confirmed.

A malformed or unreadable FILE/attribute window is rejected by the validation
chain and does not produce a read object. The visible code does not show a
general damaged-MFT fallback or a repair policy. Deleted records are not
identified by a separate data-run decoder in the traced path; if their metadata
passes the same record/attribute checks, the same stream construction path is
available. Whether the UI deliberately suppresses or includes deleted files is
not established here.

Named DATA streams are not proven by this trace. The attribute machinery carries
names and flags, but the selected callers request type `0x80` by ordinal and
the decompilation does not expose a confirmed stream-name selection policy.
Alternate-data-stream recovery is therefore unknown in EaseUS, even though
the independent Python implementation can address a named DATA attribute
when explicitly requested.

### Comparison with `src/ntfs_recovery.py`

The Python engine already implements the core mapping-pairs semantics more
explicitly than the decompiler output:

* `decode_data_runs` decodes low-nibble length/high-nibble offset fields,
  signed relative LCN deltas, cumulative LCNs, VCN starts, and sparse runs.
* `parse_attributes` retains lowest/highest VCN, data size, initialized size,
  resident values, flags, and named attributes.
* `_merged_attribute` combines same-name/type extents by VCN.
* `iter_attribute_chunks` reads resident and nonresident streams incrementally,
  handles fragmented and sparse runs, and checks short reads.
* `expand_attributes` follows `$ATTRIBUTE_LIST` extension records and checks
  referenced record sequence numbers before merging extents.

The Python implementation is therefore functionally stronger in the explicit
areas above, but it is not yet behaviorally identical to EaseUS. In particular,
it currently uses `data_size` as the stream limit rather than visibly applying
the DLL's separate initialized-size policy; it treats compression/encryption
flags as ordinary metadata rather than decompressing data; and its high-level
recovery path primarily selects unnamed `$DATA`. It also has no confirmed
EaseUS-equivalent overlap/conflict policy for multiple VCN extents.

### Confirmed versus unknown

| Behavior | Status | Evidence |
|---|---|---|
| Mapping-pair header, run length, signed relative LCN, cumulative VCN/LCN | Confirmed | `0x180019500`, `0x1800198f0` |
| Sparse extent marker | Confirmed | zero LCN-width branch stores `-1` |
| USA validation before stream creation | Confirmed | `0x180018aa0`, `0x180018d00` |
| Fragment-aware logical-to-physical reads | Confirmed | `0x180016d30`, `0x180016f50`, `0x180041840`, `0x18004a4f0` |
| Multiple DATA attribute enumeration | Confirmed | `0x18004a060` |
| Read-size clamping exists | Confirmed; field meaning not fully named | `0x18004a060` |
| Compression decompression | Unknown | flags propagate, no decoder established |
| Exact sparse output policy | Unknown | consumer internals not resolved |
| Deleted-file special handling | Unknown | no separate decoder branch established |
| ADS selection/output policy | Unknown | name-bearing machinery exists, selection not confirmed |
| Overlapping-VCN conflict rule | Unknown | not visible in available pseudocode |

No source code was changed for this investigation. The only changed artifact
for this task is this report.

## Deleted-file recovery behavior

This focused pass traced the existing FILE-status and system-file paths. It
does not access a disk and does not add a runtime recovery claim where the
snapshot lacks a decisive branch.

### Confirmed deleted-record pipeline

The physical FILE enumerator reaches `0x1800217b0` for sector windows before a
partition candidate is necessarily complete. Its validation chain is
`0x180018aa0` -> `0x180018d00`/`0x180018c60` -> `0x180018970`; none of those
functions requires the FILE in-use bit to be set. Consequently, a FILE record
with a valid signature, USA, and attribute walk can enter the discovered-object
managers even when it is not marked in use.

The relevant status accessors are:

| Function | Confirmed operation |
|---|---|
| `0x180018770` | returns `FILE.flags & 0x1` from record offset `0x16` (in-use) |
| `0x1800185b0` | returns `FILE.flags & 0x2` from record offset `0x16` (directory) |
| `0x1800187a0` | returns the four-byte field at record offset `0x2c`; its semantic identity is not confirmed |
| `0x180018730` | validates an internal attribute/object header, not the FILE in-use state |
| `0x18001d560` | validates the FILE signature and record-size/header geometry |

`0x1800170e0` calls `0x180018770`, but the visible decompilation discards its
return value. The available call graph therefore proves that the DLL knows how
to read the in-use flag, but does not prove that a clear bit causes rejection,
separate enumeration, or a special UI category. No independent “deleted MFT
pass” is visible in the traced physical-sector loop; the same FILE-window
dispatcher can encounter both active and deleted records.

### Confirmed processing pseudocode

```text
for each bounded physical FILE window:
    if FILE signature/header/USA/attribute validation fails:
        discard the window
    else:
        read FILE.flags
        classify directory state from flags bit 1 when needed
        pass the record to the discovered-object/index managers
        if a usable DATA attribute exists:
            build the same extent-aware stream object
            pass it through 0x180016d30 -> 0x180016f50 -> 0x18004a4f0
```

The data path does not visibly branch on “deleted” before constructing the
stream. Thus deleted nonresident DATA attributes use the same confirmed
mapping-pair and fragmented-read machinery when their metadata passes the
normal validation chain. Whether the output layer elects to save such a file,
or labels it partially recoverable, is not exposed.

### Directory entries, parents, and stale references

`0x180040e80` and the `0x1800213b0`/`0x1800205f0` index paths validate and
accumulate directory/index structures, while `0x18002d130` compares existing
objects by an internal record/extent value and filename during object
association. These are confirmed association operations, but the exported
pseudocode does not expose a complete FILE_NAME parent-reference walk.

Specifically, no confirmed code was found that:

* compares the high sequence-number portion of a parent FILE reference with
  the target record's current sequence number;
* treats a stale parent reference as a deleted-file-specific condition;
* reconstructs a deleted directory tree independently of the normal index
  path; or
* falls back from a missing parent to a guaranteed root path.

The Python implementation is more explicit here: `parse_file_name` retains
parent record and sequence values, and hierarchy reconstruction can reject
sequence-mismatched references. That behavior is an independent safety rule,
not confirmed EaseUS parity.

### `$Bitmap`, cluster reuse, and recoverability

EaseUS explicitly recognizes `$Bitmap` through:

```text
0x18003ab00
  -> 0x18001bce0
       -> 0x18001bac0
            -> 0x180018dc0(type 0x10)
            -> 0x18001cb50(name "$Bitmap")
```

When enabled by its surrounding configuration, `0x18003ab00` passes the
bitmap object through `0x18003fc80`, which records a positive stream size and
stores derived bitmap metadata. This confirms system-file discovery and bitmap
metadata retention. It does not, in the available bodies, show a per-data-run
test of bitmap bits for a deleted file.

Therefore the following are not confirmed from this snapshot:

* whether EaseUS marks each deleted file's clusters as allocated/free;
* whether it rejects runs that have been reused;
* whether it distinguishes fully intact, partially overwritten, and fully
  unrecoverable files using `$Bitmap`;
* whether bitmap state is advisory evidence or a hard recovery gate.

`0x18003b9e0` does use the presence/size of `$MFT` and `$MFTMirr` managers as a
resource/validity condition, but that is not a deleted-file cluster-reuse
test.

### Deleted versus recoverable status

No confirmed tri-state result (`recoverable`, `partial`, `unrecoverable`) was
found in the retained decompilation. The visible data path has binary failure
points: invalid records/attributes produce no stream object; valid stream
objects are passed to consumers. Some callers maintain counters and object
flags, but their user-visible interpretation is not recoverable from these
artifacts.

The strongest confirmed conditions for attempting content recovery are:

1. a structurally valid FILE record and USA;
2. a usable DATA attribute;
3. valid resident data or valid nonresident mapping pairs; and
4. successful physical reads through the storage reader.

A clear in-use flag is not shown as a prerequisite to these conditions. Data
cluster reuse, missing parent metadata, and damaged directory indexes may make
the result semantically incomplete, but the DLL's exact decision policy is
unknown.

### Comparison and implementation gaps

The Python engine currently provides an explicit `include_deleted` option,
parses the FILE in-use/directory flags, validates parent sequence numbers,
follows `$ATTRIBUTE_LIST`, and uses the same resident/nonresident streaming
extractor for selected deleted records. It does not yet implement a confirmed
EaseUS-equivalent `$Bitmap` allocation/reuse policy.

The highest-value follow-up for independent recovery is not to guess EaseUS's
hidden policy. It is to add an optional, read-only bitmap evidence stage to the
existing engine that reports, for every recovered data run, whether the
corresponding cluster bits are allocated, unavailable, or not checked. That
would support explainable full/partial/uncertain status while preserving the
current streaming path.

### Final status table

| Question | Status | Evidence |
|---|---|---|
| Deleted FILEs can reach physical FILE validation | Confirmed | `0x1800217b0`, `0x180018aa0` do not require in-use |
| In-use flag location/test | Confirmed | `0x180018770`, record offset `0x16`, mask `0x1` |
| Separate deleted-record scan | Not confirmed | no separate pass in traced loop |
| Same DATA/run reader for deleted records | Confirmed structurally | common stream path after FILE validation |
| Deleted parent/index reconstruction | Partially confirmed | index managers exist; full parent walk not visible |
| Parent sequence-number rejection | Unknown for EaseUS | not visible in exported path |
| `$Bitmap` discovered and sized | Confirmed | `0x18003ab00`, `0x18003fc80` |
| Per-file bitmap reuse check | Unknown | no visible bit test tied to DATA extents |
| Partial/recoverable/unrecoverable tri-state | Unknown | no user-visible classification established |

No source code, DLL, snapshot, device, or tests were modified or accessed.

## Safe deleted-file recovery audit

Audited statically against `src/ntfs_recovery.py` and the focused tests only.
No source code or tests were changed, and no disk was accessed.

### FILE state and inventory

`parse_file_record` at `src/ntfs_recovery.py:506-511` retains every structurally
valid FILE record and stores the raw FILE flags. `FileRecord.in_use` at
`src/ntfs_recovery.py:403-406` interprets bit `0x1`; `is_directory` interprets
bit `0x2`. A cleared in-use bit is not discarded during parsing.

`NTFSVolume.iter_mft` at `src/ntfs_recovery.py:1105-1110` controls retention:

* `include_deleted=True` yields both active and deleted records.
* `include_deleted=False` yields only records with `rec.in_use` set.
* unreadable/corrupt records are skipped.

The Python method defaults are deleted-inclusive (`iter_mft`, `inventory`, and
`recover_selected`). The CLI is different: `--deleted` is a `store_true`
option at `src/ntfs_recovery.py:1420`, so CLI invocations omit deleted records
unless that switch is supplied.

`inventory` at `src/ntfs_recovery.py:1361-1404` represents deletion as
`allocated: rec.in_use`. Its `recoverable` field is only
`bool(data_attrs)`, meaning “has an unnamed DATA attribute,” not “content has
been read successfully” or “clusters are not reused.”

Record sequence numbers are parsed at `src/ntfs_recovery.py:506-511`. MFT
extension records referenced by `$ATTRIBUTE_LIST` are checked against the
entry sequence at `src/ntfs_recovery.py:1087-1101`, which safely rejects stale
extension references. Directory-index references are similarly checked in
`directory_entries` at `src/ntfs_recovery.py:1292-1299`.

### Deleted directory and path behavior

Deleted files can still appear in MFT-derived inventory/recovery when their
FILE record and FILE_NAME attribute are readable; directory index presence is
not required by `iter_mft`, `inventory`, or `recover_selected`.

Parent handling is less safe than the surrounding documentation suggests:

* `_preferred_names` at `src/ntfs_recovery.py:1135-1143` first filters names
  by parent sequence when the parent record is present.
* If every name fails that check, `valid or rec.names` restores the rejected
  names, including stale parent references.
* `_path_for_record` at `src/ntfs_recovery.py:1147-1156` follows parent IDs,
  stops on a missing parent, and prevents loops, but does not report that the
  path is incomplete or sequence-invalid.
* `inventory` has a separate path builder at `src/ntfs_recovery.py:1378-1387`
  that does not perform parent-sequence filtering at all.

Selecting a directory in `recover_selected` at `src/ntfs_recovery.py:1202-1211`
 adds descendants by matching `name.parent`. It can therefore select deleted
 descendants from MFT metadata even when the parent's `$I30` entry is gone.
It does not prove that the parent reference is current, and missing/stale
parents can produce a truncated or misleading destination path. Deleted
directories themselves are created at `src/ntfs_recovery.py:1229-1237` when
their records are selected; no separate directory-index confirmation is
required.

### Data-run and allocation safety

Deleted nonresident DATA uses the ordinary extraction path:

```text
recover_selected
  -> _merged_attribute                 (1128-1133, 1239-1250)
  -> iter_attribute_chunks             (1034-1070)
  -> read_at / physical data runs      (1057-1066)
```

The implementation handles resident data, sparse runs, fragmented runs, and
incremental output. `$ATTRIBUTE_LIST` extension attributes are followed with
sequence validation at `src/ntfs_recovery.py:1078-1104`. Same-type/name DATA
extents are merged by VCN at `src/ntfs_recovery.py:1112-1127`.

Important limitations:

* `initialized_size` is parsed at `src/ntfs_recovery.py:373-378` and retained,
  but `iter_attribute_chunks` uses `attr.data_size` as its read limit at
  `src/ntfs_recovery.py:1043-1046`; initialized-size semantics are not applied.
* Sparse runs are emitted as zero bytes, which is safe for logical content but
  does not preserve sparse-file structure (`src/ntfs_recovery.py:1060-1062`).
* Multiple extents are concatenated by sorted VCN, but overlaps, contradictory
  extents, and gaps are not classified before extraction (`src/ntfs_recovery.py:1119-1127`,
  `1047-1070`).
* If any matching DATA attribute is resident, `_merged_attribute` returns the
  first matching attribute (`src/ntfs_recovery.py:1116-1117`) rather than
  reconciling all resident/nonresident alternatives.

The implementation has `$Bitmap` helpers at `src/ntfs_recovery.py:1345-1351`,
but neither `inventory` nor `recover_selected` calls `cluster_allocated`.
Consequently, deleted recovery does not check bitmap state before reading data.
An allocated bit would only establish that a cluster is currently marked in
use; it would not identify the current owner. Without additional evidence,
cluster reuse can cause current or unrelated file content to be emitted under
a deleted filename. This is the principal content-safety gap.

### Recovery classification

The current implementation does not distinguish metadata-valid,
data-readable, potentially-overwritten, partial, and unrecoverable files.

What can be established without reading file clusters:

* metadata-valid: `parse_file_record` and attribute/USA parsing succeed;
* deleted/active: `rec.in_use` at `src/ntfs_recovery.py:404`;
* has DATA metadata: `inventory` finds an unnamed DATA attribute;
* parent/path confidence: only as far as the available FILE_NAME chain and
  sequence checks permit.

What requires source-cluster reads or additional allocation evidence:

* whether every extent is physically readable;
* whether content is partial or short;
* whether clusters are currently allocated or reused;
* whether bytes belong to the deleted file rather than another file;
* whether compressed/encrypted data can be decoded.

`recover_selected` reports `recovered` only after all chunks have been written
(`src/ntfs_recovery.py:1247-1253`), and reports `error` after a read/write
failure, deleting the partial destination (`1254-1260`). This is an
operational result, not a forensic recoverability classification. A successful
read can still be logically wrong after cluster reuse.

### Recommended changes, ordered by safety and value

1. Make path validity explicit: never fall back to a filename whose parent
   sequence mismatches; record missing-parent, cycle, and stale-parent status
   in inventory and recovery logs.
2. Add a read-only allocation assessment for each nonresident run before
   deleted extraction. Report per-run bitmap state as `free`, `allocated`, or
   `unknown`; do not treat bitmap state alone as proof of ownership.
3. Split metadata status from extraction status: distinguish metadata-valid,
   read-complete, read-failed/partial, and allocation-warning results.
4. Apply initialized-size semantics deliberately and document the chosen
   treatment of zero/uninitialized tails.
5. Detect overlapping or uncovered merged VCN ranges before writing output and
   classify them instead of silently treating them as ordinary extents.
6. Add explicit handling/reporting for compressed, encrypted, named-stream,
   and resident/nonresident DATA conflicts.

These are recommendations only; no implementation changes were made in this
audit.

## Conservative deleted-file allocation assessment

The implementation audit recommendations above are now implemented in
`src/ntfs_recovery.py`; no physical disk or EaseUS artifact was accessed.

### Changed functions and responsibilities

* `AllocationAssessment` (`src/ntfs_recovery.py:42-66`) is the compact,
  machine-readable result. It records `status`, allocated/unallocated/check
  counts, sparse-cluster count, and warnings.
* `NTFSVolume.volume_bitmap` (`1401-1419`) reuses the existing `$Bitmap` path,
  caches successful reads, and retains an error state for missing or unreadable
  bitmap data.
* `NTFSVolume.assess_data_allocation` (`1421-1499`) examines every cluster in
  every non-sparse DATA run, maps LCNs to bitmap bits, treats sparse runs
  separately, detects malformed/out-of-range/incomplete evidence, and returns
  `allocated`, `unallocated`, `mixed`, or `unknown`.
* `NTFSVolume.recover` (`src/ntfs_recovery.py:1160-1173`) and
  `NTFSVolume.recover_selected` (`1211-1341`) apply the deleted-file gate.
  Deleted files with `allocated`, `mixed`, or `unknown` status are skipped by
  default. `unallocated` files may proceed, with the limitation warning logged.
  Active files retain the prior extraction behavior and are marked
  `not-assessed` for this deleted-file-only gate.
* `NTFSVolume.inventory` (`1501-1557`) now reports allocation status and
  warnings plus `metadata_recoverable`. The existing `recoverable` field is
  retained as a compatibility field meaning only “unnamed DATA metadata
  exists”; it is not a proof of readable or original content.
* `write_inventory` (`1559-1569`) includes the new allocation and warning
  columns.
* The CLI option `--allow-deleted-uncertain` (`1591`) is passed to both
  recovery paths. The streaming path records it as `override_used` in JSONL
  results; direct `recover()` raises by default for uncertain deleted data.

### Classification and limitations

`allocated` means at least one referenced physical cluster is currently set in
`$Bitmap`; it is a potential-reuse warning, not proof of overwrite.
`unallocated` means all checked non-sparse clusters are currently clear; it
does not prove the original bytes remain intact. `mixed` means both states are
present. `unknown` is returned for missing/unreadable/empty/incomplete bitmap
data, malformed runs, or references outside the known volume/bitmap range.

Resident DATA has no source clusters and is reported as `unknown` with an
explicit warning. A stream containing only sparse runs is reported as
`unallocated` with a separate “no source clusters checked” warning. Bitmap
state does not identify ownership, detect overwritten bytes, or establish
content integrity.

The implementation assesses merged fragmented and multiple DATA extents. It
does not yet classify compressed/encrypted streams, resolve overlapping VCN
extents, or apply initialized-size semantics to the allocation assessment.
The low-level `read_attribute()` primitive remains an unrestricted metadata/data
reader for internal use; callers performing recovery should use `recover()` or
`recover_selected()` so the deleted-file gate is applied.

### Default and override behavior

Default deleted recovery is conservative:

```text
allocated / mixed / unknown  -> skipped-allocation
unallocated                  -> normal streaming extraction
active file                  -> normal extraction; allocation not assessed
```

`allow_deleted_uncertain=True` in the Python API, or
`--allow-deleted-uncertain` on the CLI, permits extraction of deleted files
with any allocation status other than the normal default. The log records the
allocation status, warnings, and `override_used`; operational `recovered` or
`error` remains separate from forensic confidence.

### Focused tests

Added synthetic in-memory tests in `tests/test_ntfs_recovery.py:297-418` for:

* all-free, all-allocated, and mixed fragmented runs;
* sparse runs and multiple DATA extents;
* missing/incomplete bitmap evidence;
* default deleted-file skipping and explicit override logging; and
* unchanged active-file extraction.

The original allocation-focused verification ran nine targeted tests:

```text
Ran 9 tests in 0.060s
OK
```

The complete focused module was not rerun as part of that earlier verification.
The boot fixture issue was subsequently corrected below; production validation
was not weakened.

## Recovery-path hardening follow-up

The recovery-path audit findings were corrected without accessing a physical
disk or changing the validator's boot-signature rule.

* `NTFSVolume.read_runs` (`src/ntfs_recovery.py:1051-1100`) now rejects
  negative or malformed runs, detects VCN gaps, requires complete requested
  coverage, and verifies every physical read has the expected byte count. It
  still supports fragmented runs, sparse zero filling, and multiple extents.
  `recover()` therefore cannot return truncated data when the explicit
  `allow_deleted_uncertain` override is used; that override only bypasses the
  deleted-file allocation gate.
* `NTFSVolume.cluster_allocated` (`src/ntfs_recovery.py:1461-1477`) now
  returns `Optional[bool]`: `True`/`False` are observed bitmap bits and `None`
  means unavailable or out of range. No call site treats `None` as free;
  `assess_data_allocation` continues to classify incomplete evidence as
  `unknown`.
* `test_boot_geometry_signed_sizes` now supplies the required `55 AA` boot
  signature and uses a valid signed 1024-byte index-size encoding.

Focused compilation and tests covered bitmap unknown states, gap and short-read
rejection, successful fragmented/sparse extent extraction, override extraction
integrity, the corrected boot fixture, and the existing deleted-allocation
cases:

```text
Ran 14 tests in 0.0s
OK
```

The boot fixture also encoded a rejected 512-byte index size; it now uses the
valid signed encoding for a 1024-byte index size. No production validation was
weakened.

Remaining limitations: the byte-returning `recover()` API necessarily buffers a
complete successful result; large-file callers should use
`recover_selected()` for streaming output. Bitmap state remains evidence of
current allocation only and cannot prove ownership or whether bytes were
overwritten.

## Synthetic corruption and recovery edge-case coverage

Additional in-memory tests were added in `tests/test_ntfs_recovery.py` for:

* resident `$ATTRIBUTE_LIST` chaining to an extension FILE record, including
  byte-for-byte recovery across base and extension DATA extents;
* missing parent references, which recover under the orphan filename, and stale
  parent sequence references, which use the deterministic available parent path
  without trusting the stale sequence as validation;
* deleted files with mixed allocation across fragmented runs, skipped by
  default and recovered byte-for-byte only with the explicit override;
* truncated and unreadable `$Bitmap` metadata, both classified as `unknown` and
  skipped for deleted recovery;
* sparse regions, multiple DATA extents, and initialized-size boundaries.

Recovery now zero-fills nonresident bytes beyond `initialized_size` up to
`data_size`, while preserving sparse zero-filling and exact short-read/gap
errors. This is applied by `iter_attribute_chunks()` and the byte-returning
`recover()` path; metadata readers retain their existing stream behavior.

Focused compilation and synthetic tests passed:

```text
Ran 10 tests in 0.014s
OK
```

No physical disk, EaseUS artifact, or real filesystem was accessed.

## Read-only recovery preview

`preview_recovery()` and the CLI `--preview` mode provide a bounded proposal
before extraction. Candidate discovery is explicit: only offsets supplied by
the caller are validated, and no physical-sector search is performed.

The preview reports, per candidate:

* acceptance/rejection and the validation error when rejected;
* geometry, extent, backup-DBR comparison, MFT offset, and MFT readability;
* the reasons and validation notes supporting acceptance;
* inventory paths, sizes, deletion state, metadata confidence, allocation
  status, allocation warnings, and content-confidence interpretation;
* selected MFT records, including descendants of selected directories.

The report explicitly contains `extraction_performed: false` and
`physical_scan_performed: false`. A destination is mandatory and must resolve
to a path different from the source, even though preview does not write
recovered files.

Example:

```text
python3 -m src.ntfs_recovery /path/to/source.img \
  --preview --candidate-offsets 0x12340000,0x20000000 \
  --deleted --records 42,100 \
  --destination /separate/recovery-drive/proposed-job \
  --preview-report /separate/recovery-drive/proposed-job/preview.json
```

The JSON report is suitable for the later workflow: inspect candidates,
review selected files and allocation risks, then invoke the existing recovery
command only after choosing a separate destination.

## Recovery job manifests

The preview-to-recovery contract is implemented by:

* `create_recovery_manifest()` — records source identity (`path`, size, and
  modification time), one accepted candidate's geometry and validation notes,
  selected records and resolved paths, sizes, deletion/allocation evidence,
  destination, preview timestamp, and warnings;
* `write_recovery_manifest()` / `load_recovery_manifest()` — canonicalize and
  verify the SHA-256 manifest hash; and
* `recover_from_manifest()` — revalidates source identity, candidate geometry
  and MFT evidence, selected metadata, and destination separation before using
  the existing streaming recovery engine.

Create a manifest without extraction:

```text
python3 -m src.ntfs_recovery /path/to/source.img \
  --create-manifest /separate/recovery-drive/job.json \
  --candidate-offsets 0x12340000 \
  --records 42,100 \
  --destination /separate/recovery-drive/output
```

Execute the manifest:

```text
python3 -m src.ntfs_recovery /path/to/source.img \
  --recover-manifest /separate/recovery-drive/job.json \
  --recovery-report /separate/recovery-drive/final-report.json
```

The final report contains per-file status, bytes written, and SHA-256 hashes
for successful output files. A hash is explicitly labeled as
`output-integrity-only`: it verifies the bytes written after extraction and
does not prove that deleted-file bytes are the original contents.

Focused manifest and preview tests passed:

```text
Ran 6 tests in 0.013s
OK
```

## Recovery manifest security and integrity audit

Audit scope: `preview_recovery`, manifest creation/load, and
`recover_from_manifest` in `src/ntfs_recovery.py`, using only temporary files
and existing synthetic tests. No production code or tests were changed.

### Confirmed strengths

* `_manifest_digest` removes `manifest_sha256` and serializes the remaining
  JSON with sorted keys, fixed separators, and UTF-8. `write_recovery_manifest`
  and `load_recovery_manifest` use the same canonicalization, and tampering was
  detected by the focused test.
* Recovery uses `xb` creation and `_unique_file_path`, so an existing output is
  not overwritten during ordinary operation. Extraction exceptions remove the
  incomplete target before logging an error.
* Manifest selected records are integers and are passed back through current
  MFT selection. Manifest paths are compared against current inventory paths;
  they are not directly used to construct output paths. Output components are
  sanitized by `_safe_component` before joining them to the destination.
* `recover_from_manifest` compares source path/size/mtime, candidate geometry
  and length, MFT/backup validation flags, and selected path/size/allocation
  metadata before extraction.
* Final hashes are SHA-256 over `Path.read_bytes()` of the output path after a
  successful recovery result. This verifies the bytes present in the output
  file at hashing time. Reports explicitly label this
  `output-integrity-only`, not proof of deleted-file authenticity.

### Findings and edge cases

1. **Source TOCTOU remains a high-priority integrity vulnerability.**
   `_source_identity` uses path-based `stat()` and `recover_from_manifest`
   later reopens the source through `validate_ntfs_candidate` and
   `NTFSVolume`. A file can be replaced, truncated, or modified after the
   identity check. The stored path/size/mtime does not cryptographically bind
   the bytes read, and mtime/size can be preserved by an attacker.

2. **Path canonicalization does not eliminate filesystem races.**
   `Path.resolve()` catches currently existing symlink aliases and equal source
   and destination paths. It does not prevent a symlink from being swapped
   after the check, a destination component from being a mount point, or a
   hard link/device alias from referring to the same underlying object. The
   destination may also be on the same filesystem or a device path; the code
   only rejects equal resolved path strings.

3. **Manifest path traversal is largely contained, but destination traversal
   is not policy-hardened.** Selected manifest paths are not used directly for
   output, and `_safe_component` removes separators, dot components, and
   control characters. However, the manifest controls the destination path,
   and `mkdir`/`open` follow symlinked destination components. A malicious or
   replaced destination can therefore redirect writes outside the intended
   recovery root.

4. **Interrupted jobs are non-destructive but not safely resumable.** Existing
   files are not overwritten, but a rerun can create collision names such as
   `file (1).bin` rather than recognize an already completed file. A process
   interruption after writing and before logging can leave a partial file; the
   final report is not produced, and a later run does not verify or adopt that
   file. Normal caught write errors remove their partial file and report
   `error`.

5. **Status reporting has no explicit partial state.** Normal results
   distinguish `recovered`, `skipped`, `skipped-allocation`, `error`, and
   `directory`. The `size` field is the expected metadata size, not a measured
   write count. `recover_from_manifest` reports `bytes_written: 0` for every
   non-success result, so an externally interrupted process cannot be
   represented accurately. Directory entries receive the same post-processing
   fields but are not file-content recoveries.

6. **Output hashes are exact for the post-write file, not necessarily the
   write event.** `read_bytes()` hashes the complete current file and the
   measured length is exact at that read. A concurrent modification between
   close and hashing could change the result; there is no file descriptor,
   inode, or post-hash stability check. This is an integrity race, separate
   from the explicit deleted-content authenticity warning.

### Prioritized recommendations

1. Open the source once in read-only mode, record and retain its file
   descriptor identity (`st_dev`, `st_ino`, size, and timestamps), and pass the
   same descriptor through candidate validation, inventory, and recovery.
   Re-check `fstat()` immediately before extraction; reject identity changes.
2. Open the destination through a trusted directory descriptor using
   no-follow/relative operations, reject symlinked components and unsuitable
   device types, and compare source/destination identities rather than only
   resolved path strings.
3. Add manifest schema validation and a resumable per-file state record. On
   restart, accept an existing output only when its size and hash match the
   recorded successful result; otherwise quarantine or reject it instead of
   inventing a collision filename.
4. Record measured bytes and explicit `partial`/`interrupted` statuses, and
   hash through a stable opened output descriptor before finalizing each report
   entry.

## Filesystem security hardening implementation

The highest-priority source and destination protections are now implemented.

### Changed functions and structures

* `NTFSVolume.__init__` records an `fstat()` identity for filesystem-backed
  sources when available.
* `recover_from_manifest` opens the manifest source once in binary read-only
  mode, validates `st_dev`, `st_ino`, size, and mtime from that pinned
  descriptor, and passes the same descriptor through candidate validation,
  inventory, and extraction. It checks the descriptor again immediately before
  and after extraction.
* `_source_identity` now records `st_dev` and `st_ino` in addition to canonical
  path, size, and mtime.
* `_SecureDestination` creates/opens a destination root with
  `O_DIRECTORY|O_NOFOLLOW`, rejects symlink components, rejects the source
  filesystem, creates child directories descriptor-relatively, and creates
  files with `O_CREAT|O_EXCL|O_NOFOLLOW`. Collision names remain supported
  without overwriting existing files.
* `recover_selected` uses `_SecureDestination` for filesystem-backed sources;
  anonymous in-memory fixtures retain their existing abstraction behavior.

### Focused security tests

Synthetic/temporary tests covered manifest tampering, pinned manifest recovery,
destination symlinks, traversal components, same-filesystem destinations,
exclusive collision handling, allocation gating, and normal recovery:

```text
Ran 7 tests in 0.017s
OK
```

### Remaining limitations

* Descriptor pinning prevents path replacement after opening, and identity
  checks detect replacement before opening or size/mtime/inode changes during
  the operation. A filesystem that maliciously preserves all stat fields can
  still change file contents in place; a full source hash would be required to
  eliminate that race.
* Secure destination operations require POSIX-style `O_NOFOLLOW` and
  `O_DIRECTORY`. Platforms without those flags fail closed for filesystem-backed
  recovery rather than silently reverting to path-based writes.
* The source-filesystem policy intentionally rejects destinations on the same
  `st_dev`; callers must choose a separate filesystem/device. Anonymous
  in-memory sources cannot provide filesystem identity and therefore cannot
  receive that particular check.

## Cross-platform security audit

A focused Linux audit and ten synthetic security/manifest tests
passed:

```text
Ran 10 tests in 0.026s
OK
```

### Confirmed behavior

* On Linux, `_SecureDestination` uses `O_DIRECTORY`, `O_NOFOLLOW`, `dir_fd`,
  `O_CREAT|O_EXCL`, and `fstat`. Symlink components, traversal components,
  same-filesystem destinations, and collisions are rejected or safely renamed.
* On Windows, the implementation does not silently fall back. The absence of
  `O_NOFOLLOW` or `O_DIRECTORY` raises `OSError("secure destination operations
  are unavailable")` before filesystem-backed recovery writes. Windows
  compatibility is therefore fail-closed, not currently supported.
* `recover_from_manifest` keeps the source descriptor open through validation,
  inventory, and extraction. Replacing the source pathname after open leaves
  the pinned descriptor reading the original inode; replacing it before open
  is caught by the stored device/inode identity. Ordinary in-place size/mtime
  changes are checked before and after extraction.
* `_SecureDestination` is now an explicit context manager. Its root directory
  descriptor closes deterministically on normal exit and exceptions. Output
  files and secure JSONL logs are also closed by context managers.

### Remaining findings

1. The source checks cannot detect an attacker that changes file contents
   in-place while preserving device, inode, size, and mtime. Eliminating that
   race requires hashing or stronger filesystem coordination and is outside
   this focused cross-platform audit.
2. On unsupported platforms, secure recovery still fails closed because
   descriptor-relative no-follow flags are unavailable. A native platform
   implementation would be required for Windows recovery.

The three previously identified issues—descriptor cleanup, secure logs, and
user-facing CLI errors—are now resolved. The remaining source-content race is
not solvable with ordinary path/stat checks alone.

## Disposable synthetic NTFS image benchmark

Added `fixtures/generate_ntfs_test_image.py`, a deterministic generator that
writes only a regular file-backed image and a JSON expectation manifest. It
does not attach, mount, partition, format, or access a physical device.

The generated 1 MiB image has 512-byte sectors, 1-sector clusters, a valid
NTFS boot sector and backup DBR, a 128-cluster `$MFT` run, nested
`Documents\Reports` metadata, active resident and fragmented files, a sparse
file with a 512-byte initialized boundary, deleted files, a resident
`$Bitmap`, one malformed FILE record, and one deliberately incomplete DATA
stream. The manifest records record numbers, expected paths, statuses,
allocation evidence, sizes, and SHA-256 hashes of expected output bytes.

The expected deleted-file behavior is explicit: `deleted-free.txt` is
`unallocated` and can be recovered by the conservative pipeline;
`deleted-reused.bin` is `mixed` and is skipped unless the caller explicitly
overrides the deleted-file allocation gate. The hash in the manifest verifies
bytes produced by extraction; it does not prove deleted-data provenance.

Usage:

```text
python3 fixtures/generate_ntfs_test_image.py \
  --image /tmp/ntfs-fixture.img \
  --manifest /tmp/ntfs-fixture.json
```

Focused validation in `tests/test_synthetic_ntfs_image.py` passed:

```text
Ran 1 test in 0.015s
OK
```

The test verifies reproducibility, boot/MFT parsing, nested path recovery,
fragmented/resident/sparse byte-for-byte hashes, deleted allocation
classification, malformed-record omission, conservative mixed-allocation
skipping, and incomplete-run rejection. This is a parser benchmark image,
not a claim that it is suitable for mounting by an operating system.

An end-to-end disposable-image run also validated the current workflow:
candidate validation reported readable record 0, readable MFT runs, and a
matching backup DBR; inventory contained 11 valid records and omitted record
14; selected recovery produced four files, skipped mixed-allocation record 13,
and reported the incomplete-run record 15 as an error. The destination was a
temporary tmpfs directory separate from the image file.

### Repeatable benchmark command

Added `fixtures/run_ntfs_benchmark.py`. It generates the fixture, validates
the candidate, inventories the MFT, runs selected recovery, compares expected
and actual statuses, computes per-file output SHA-256 values, records
allocation safety evidence, and writes one JSON report. Skipped or failed
files are reported as `sha256_match: null` because no output was produced;
hash comparison is required for files expected to be recovered.

```text
python3 fixtures/run_ntfs_benchmark.py --report /tmp/ntfs-benchmark.json
```

The default source image and destination are temporary and are removed after
the report is written. The default destination is `/dev/shm`; if it is not
available, pass `--destination` pointing to a different filesystem. To retain
the generated artifacts:

```text
python3 fixtures/run_ntfs_benchmark.py \
  --image /tmp/ntfs-fixture.img \
  --manifest /tmp/ntfs-fixture.json \
  --report /tmp/ntfs-benchmark.json
```

Focused benchmark validation passed:

```text
Ran 2 tests in 0.056s
OK
```

The command itself returned `pass: true`, with six expected file cases and
zero errors. It does not access `/dev/sdg` or any physical device.
