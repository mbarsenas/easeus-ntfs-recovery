# EaseUS directory-reference validation

The supplied EaseUS listing is treated as a comparison manifest only. Names
and counts are not embedded in the recovery engine.

## Implemented reconstruction improvements

* `FILE_NAME` parent references now preserve the parent sequence number.
  Parent links whose sequence does not match the target FILE record are not
  preferred for path construction; orphaned names remain available as fallback
  metadata.
* Directory index entries preserve the 48-bit MFT number and 16-bit sequence
  number separately.
* `$I30` entries from `INDEX_ROOT` and `INDEX_ALLOCATION` are deduplicated.
* `INDEX_ALLOCATION` blocks are filtered through the directory `$BITMAP` when
  that attribute is present.
* Stale index references are rejected by reading the referenced FILE record and
  comparing its sequence number.
* `$ATTRIBUTE_LIST` is parsed and extension FILE records are followed when the
  referenced FILE sequence matches. Their `FILE_NAME` and fragmented `$DATA`
  attributes are merged into the base record.
* Multiple nonresident segments for one named stream are merged by VCN before
  streaming recovery.
* `directory_index_counts()` reports direct `$I30` children.
* `directory_subtree_counts()` and `compare_reference_counts()` report the
  recursive item counts that better correspond to the EaseUS UI values such as
  `Xbox (23362)` and `Argo (250)`.

## Reference comparison manifest

For a future targeted validation, pass paths such as these to
`compare_reference_counts()`:

```python
expected = {
    r"\Users": 31,
    r"\Program Files": 169,
    r"\Xbox": 23362,
    r"\SeagateVolume": 0,
    r"\SRECYCLE.BIN": 2580,
    r"\System Volume Information": 6,
    r"\WindowsApps": 0,
    r"\Office": 1,
    r"\Camera": 3,
    r"\MyStuff": 80,
    r"\Knowledge Base": 54,
    r"\VirtualBox VMs": 8,
    r"\OpenAI": 0,
    r"\Microsoft 365 Development Tenant": 1,
    r"\.github": 3,
    r"\openai-quickstart-node-master": 9,
    r"\CDW": 0,
    r"\NTT": 1,
    r"\jukebox1": 357,
    r"\jukebox": 359,
    r"\caffeine": 2,
    r"\Shared_Files": 2,
    r"\iPhone": 252,
    r"\MSI6c06c.tmp": 0,
    r"\GIT": 30,
    r"\Hudson Advisors": 1,
    r"\AGII - Azure": 4,
    r"\Logs": 2,
    r"\Tools": 232,
    r"\Argo": 250,
}
```

The displayed EaseUS counts may include files and directories recursively;
they should not be compared directly with `directory_index_counts()`, which is
intentionally a direct-child structural check.

## Remaining limitations

The current attribute-list implementation handles ordinary extension-record
chains, but it does not yet reconstruct every malformed/cyclic list or every
multi-base-record case. Damaged index ordering, missing `$BITMAP`, deleted
directory records with stale parent references, and missing `FILE_NAME`
attributes can still produce orphaned paths. File-type category totals shown by
EaseUS are not currently implemented; they require content-signature
classification and are independent of hierarchy reconstruction.
