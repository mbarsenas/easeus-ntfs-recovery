#!/usr/bin/env python3
"""Generate a separate disposable VHDX with one deleted nonresident file.

The original synthetic NTFS image and the supplied Windows-created VHDX are
not modified.  This fixture wraps a copy of the deterministic raw synthetic
image in a single fully-present dynamic VHDX block and adds record 16, whose
fragmented clusters remain marked free in ``$Bitmap``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Optional

# Allow the documented script form (``python3 fixtures/...py``) to import the
# project-local fixture and recovery modules.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fixtures.generate_ntfs_test_image import (
    CLUSTER,
    MFT_LCN,
    MFT_RECORD_SIZE,
    _file_record,
    _filename_value,
    _nonresident_attr,
    _resident_attr,
    _write_cluster,
    build_image,
)
from src.ntfs_recovery import VHDXReader


BLOCK_SIZE = 1024 * 1024
PAYLOAD_OFFSET = 0x500000
HOST_SIZE = PAYLOAD_OFFSET + BLOCK_SIZE


def _crc32c(data: bytes) -> int:
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def _checksum(buf: bytearray, offset: int) -> None:
    buf[offset:offset + 4] = b"\0" * 4
    struct.pack_into("<I", buf, offset, _crc32c(bytes(buf)))


def _add_deleted_file(raw: bytearray) -> tuple[bytes, dict[str, object]]:
    content = (b"VHDX-DELETED-NONRESIDENT-" + bytes(range(64))).ljust(1024, b"Z")
    runs = [(340, 1), (345, 1)]
    record = _file_record(
        16, 2, 0,
        [
            _resident_attr(0x30, _filename_value(
                "deleted-vhdx.bin", 7, 1, len(content)), 1),
            _nonresident_attr(0x80, runs, len(content), len(content), 2),
        ],
    )
    record_offset = MFT_LCN * CLUSTER + 16 * MFT_RECORD_SIZE
    raw[record_offset:record_offset + MFT_RECORD_SIZE] = record
    _write_cluster(raw, 340, content[:CLUSTER])
    _write_cluster(raw, 345, content[CLUSTER:])
    relative_path = r"\Documents\deleted-vhdx.bin"
    return content, {
        "path": relative_path,
        "record": 16,
        "status": "recovered",
        "allocation_status": "unallocated",
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "runs": [{"lcn": lcn, "length": length, "vcn": index}
                 for index, (lcn, length) in enumerate(runs)],
    }


def _vhdx_wrap(raw: bytes) -> bytes:
    if len(raw) != BLOCK_SIZE:
        raise ValueError("the synthetic source must occupy exactly one VHDX block")
    image = bytearray(HOST_SIZE)
    image[:8] = b"vhdxfile"
    for offset, sequence in ((0x10000, 1), (0x20000, 2)):
        header = bytearray(0x1000)
        header[:4] = b"head"
        struct.pack_into("<Q", header, 8, sequence)
        _checksum(header, 4)
        image[offset:offset + len(header)] = header

    regions = bytearray(0x10000)
    regions[:4] = b"regi"
    struct.pack_into("<I", regions, 8, 2)
    entries = [(VHDXReader.BAT_GUID, 0x300000, 0x100000, 1),
               (VHDXReader.METADATA_GUID, 0x200000, 0x100000, 1)]
    for index, (identifier, offset, length, flags) in enumerate(entries):
        pos = 0x10 + index * 32
        regions[pos:pos + 16] = identifier.bytes_le
        struct.pack_into("<QII", regions, pos + 16, offset, length, flags)
    _checksum(regions, 4)
    image[0x30000:0x40000] = regions
    image[0x40000:0x50000] = regions

    metadata = bytearray(0x100000)
    metadata[:8] = b"metadata"
    struct.pack_into("<H", metadata, 0x0a, 4)
    values = [
        (VHDXReader.FILE_PARAMETERS_GUID, struct.pack("<II", BLOCK_SIZE, 0)),
        (VHDXReader.VIRTUAL_SIZE_GUID, struct.pack("<Q", len(raw))),
        (VHDXReader.LOGICAL_SECTOR_GUID, struct.pack("<I", 512)),
        (VHDXReader.PHYSICAL_SECTOR_GUID, struct.pack("<I", 512)),
    ]
    value_offset = 0x1000
    for index, (identifier, value) in enumerate(values):
        pos = 0x20 + index * 32
        metadata[pos:pos + 16] = identifier.bytes_le
        struct.pack_into("<III", metadata, pos + 16, value_offset, len(value), 4)
        metadata[value_offset:value_offset + len(value)] = value
        value_offset += len(value)
    image[0x200000:0x300000] = metadata

    struct.pack_into("<Q", image, 0x300000, 6 | PAYLOAD_OFFSET)
    image[PAYLOAD_OFFSET:PAYLOAD_OFFSET + len(raw)] = raw
    return bytes(image)


def build_fixture() -> tuple[bytes, dict[str, object]]:
    raw, manifest = build_image()
    mutable = bytearray(raw)
    _content, new_file = _add_deleted_file(mutable)
    vhdx = _vhdx_wrap(bytes(mutable))
    output_manifest = dict(manifest)
    output_manifest["format"] = "easeus-ntfs-recovery.synthetic-deleted-vhdx.v1"
    output_manifest["virtual_size"] = len(raw)
    output_manifest["host_size"] = len(vhdx)
    output_manifest["files"] = list(manifest["files"]) + [new_file]
    output_manifest["notes"] = list(manifest["notes"]) + [
        "deleted-vhdx.bin is newly added in record 16 with fragmented, unallocated DATA runs",
        "the original missing project-notes.txt and fragmented-test.bin remain absent and are not recoverable",
    ]
    output_manifest["image_sha256"] = hashlib.sha256(vhdx).hexdigest()
    return vhdx, output_manifest


def generate_fixture(image_path: str | Path, manifest_path: str | Path) -> dict[str, object]:
    image, manifest = build_fixture()
    image_path = Path(image_path)
    manifest_path = Path(manifest_path)
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    image_path.write_bytes(image)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    manifest = generate_fixture(args.image, args.manifest)
    print(json.dumps({"image": str(args.image), "manifest": str(args.manifest),
                      "virtual_size": manifest["virtual_size"],
                      "image_sha256": manifest["image_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
