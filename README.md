# EaseUS NTFS Recovery

An independent NTFS data-recovery project focused on locating deleted files and recovering their contents safely to a separate destination.

The goal is to build a practical recovery engine that can analyze NTFS volumes, identify deleted files, reconstruct their data, and extract selected files without modifying the original source volume.

> **Status: Experimental / Active Development**
>
> Recovery capabilities are being developed and validated against synthetic NTFS fixtures and disposable virtual disk images. This project is not yet represented as production-ready or guaranteed to recover every deleted file.

## Project Goals

- Locate deleted files and directories in NTFS volumes.
- Reconstruct file metadata and data from NTFS structures.
- Recover selected files to a separate destination.
- Preserve the original source volume by accessing it read-only.
- Validate recovered files using SHA-256 hashes where applicable.
- Maintain recovery manifests and diagnostic logs.

## Current Capabilities

The recovery engine includes work on:

- NTFS boot-sector and backup boot-sector validation.
- Master File Table (MFT) bootstrap and record parsing.
- FILE record validation and update-sequence-array processing.
- Discovery and analysis of deleted MFT records.
- Attribute-list and extension-record handling.
- Directory and index reconstruction.
- `$INDEX_ALLOCATION` bitmap filtering and stale sequence validation.
- Resident and non-resident `$DATA` attribute handling.
- Multiple data extents, fragmented streams, and sparse data.
- Initialized-size handling during extraction.
- Allocation-state checks using the NTFS `$Bitmap`.
- Selected-file extraction to a separate destination.
- SHA-256 verification, recovery manifests, and JSONL diagnostic logs.

## Safety Design

Protecting the source volume is a core design requirement.

- Source volumes are accessed read-only.
- Recovered files are written to a separate destination.
- The recovery process is designed to avoid modifying source filesystem metadata.
- Extraction includes destination-path and allocation-safety checks.
- Testing is performed using synthetic fixtures and disposable virtual disk images.

**Important:** Do not use this experimental software as a substitute for professional recovery services when data is irreplaceable. No recovery tool can guarantee recovery in every situation.

## Testing and Validation

Development and testing have included:

- Synthetic NTFS filesystem fixtures.
- Disposable virtual disk images, including VHDX testing.
- Fragmented deleted-file recovery scenarios.
- Validation of recovered content against original SHA-256 hashes.
- Tests covering MFT parsing, data-run reconstruction, allocation checks, and extraction behavior.

A fragmented deleted-file test successfully reconstructed the file and produced content matching the original SHA-256 hash.

These results demonstrate specific tested capabilities; they do not establish universal recovery success.

## Project Direction

The project is being developed as a standalone NTFS recovery engine, with future work potentially including:

- Broader NTFS compatibility testing.
- Additional deleted-file and directory recovery scenarios.
- Improved recovery reporting and diagnostics.
- A graphical user interface.
- Expanded automated testing against more complex filesystem layouts.

## Disclaimer

This is an independent software project. It is not affiliated with, endorsed by, or sponsored by EaseUS.

EaseUS software has been used as a reference point for understanding recovery behavior. This project does not include proprietary EaseUS source code.

Use this software at your own risk. Always preserve the original storage device and recover files to a different storage destination.

## License

License information will be added when the project license is selected.
