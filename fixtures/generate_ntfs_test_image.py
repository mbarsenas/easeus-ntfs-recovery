#!/usr/bin/env python3
"""Generate a deterministic, disposable NTFS-like test image.

This deliberately creates only a regular image file.  It does not use loop
devices, partition tools, formatters, or physical devices.  The resulting
metadata is sufficient for this project's read-only NTFS parser and is meant
for repeatable parser/recovery benchmarks, not for mounting as a general
purpose Windows volume.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Iterable, Optional


BPS = 512
SPC = 1
CLUSTER = BPS * SPC
TOTAL_SECTORS = 2048
IMAGE_SIZE = TOTAL_SECTORS * BPS
MFT_LCN = 16
MFT_MIRROR_LCN = 160
MFT_RECORD_SIZE = 1024
MFT_CLUSTERS = 128


def _put(buf: bytearray, offset: int, fmt: str, value: int) -> None:
    struct.pack_into(fmt, buf, offset, value)


def _signed_width(value: int) -> int:
    for width in range(1, 9):
        if -(1 << (width * 8 - 1)) <= value < (1 << (width * 8 - 1)):
            return width
    raise ValueError(f"mapping-pair delta is too large: {value}")


def encode_runs(runs: Iterable[tuple[Optional[int], int]], start_vcn: int = 0) -> bytes:
    """Encode ``(absolute LCN or None, cluster length)`` mapping pairs."""
    result = bytearray()
    previous_lcn = 0
    for lcn, length in runs:
        if length <= 0:
            raise ValueError("run lengths must be positive")
        length_width = _signed_width(length)
        length_bytes = length.to_bytes(length_width, "little", signed=False)
        if lcn is None:
            offset_width = 0
            offset_bytes = b""
        else:
            delta = lcn - previous_lcn
            offset_width = _signed_width(delta)
            offset_bytes = delta.to_bytes(offset_width, "little", signed=True)
            previous_lcn = lcn
        result.append((offset_width << 4) | length_width)
        result.extend(length_bytes)
        result.extend(offset_bytes)
    result.append(0)
    return bytes(result)


def _filename_value(name: str, parent: int, parent_sequence: int = 1,
                    size: int = 0, directory: bool = False) -> bytes:
    encoded = name.encode("utf-16le")
    value = bytearray(0x42 + len(encoded))
    _put(value, 0, "<Q", (parent_sequence << 48) | parent)
    _put(value, 0x28, "<Q", size)
    _put(value, 0x30, "<Q", size)
    _put(value, 0x38, "<I", 0x10000000 if directory else 0x80)
    value[0x40] = len(name)
    value[0x41] = 1  # Win32 namespace
    value[0x42:] = encoded
    return bytes(value)


def _resident_attr(attr_type: int, value: bytes, instance: int) -> bytes:
    value_offset = 0x18
    length = (value_offset + len(value) + 7) & ~7
    attr = bytearray(length)
    _put(attr, 0, "<I", attr_type)
    _put(attr, 4, "<I", length)
    attr[8] = 0
    _put(attr, 12, "<H", instance)
    _put(attr, 16, "<I", len(value))
    _put(attr, 20, "<H", value_offset)
    attr[value_offset:value_offset + len(value)] = value
    return bytes(attr)


def _nonresident_attr(attr_type: int, runs: list[tuple[Optional[int], int]],
                      data_size: int, initialized_size: int, instance: int,
                      lowest_vcn: int = 0) -> bytes:
    pairs = encode_runs(runs, lowest_vcn)
    run_offset = 0x40
    length = (run_offset + len(pairs) + 7) & ~7
    attr = bytearray(length)
    _put(attr, 0, "<I", attr_type)
    _put(attr, 4, "<I", length)
    attr[8] = 1
    _put(attr, 12, "<H", instance)
    _put(attr, 16, "<q", lowest_vcn)
    highest_vcn = lowest_vcn + sum(length for _, length in runs) - 1
    _put(attr, 24, "<q", highest_vcn)
    _put(attr, 32, "<H", run_offset)
    _put(attr, 40, "<I", 0)  # compression unit
    _put(attr, 48, "<Q", data_size)
    _put(attr, 56, "<Q", initialized_size)
    attr[run_offset:run_offset + len(pairs)] = pairs
    return bytes(attr)


def _file_record(number: int, sequence: int, flags: int,
                 attrs: list[bytes], malformed: bool = False) -> bytes:
    record = bytearray(MFT_RECORD_SIZE)
    record[:4] = b"FILE"
    _put(record, 4, "<H", 0x30)
    _put(record, 6, "<H", 3)  # USA plus two sector replacement words
    _put(record, 16, "<H", sequence)
    _put(record, 20, "<H", 0x38)
    _put(record, 22, "<H", flags)
    pos = 0x38
    for attr in attrs:
        if pos + len(attr) + 8 > len(record):
            raise ValueError(f"record {number} attributes do not fit")
        record[pos:pos + len(attr)] = attr
        pos += len(attr)
    if malformed:
        # The parser must reject this record without affecting neighboring ones.
        _put(record, pos, "<I", 0x90)
        _put(record, pos + 4, "<I", 0x7fffffff)
    else:
        _put(record, pos, "<I", 0xffffffff)
    _put(record, 0x18, "<I", pos + 8)
    _put(record, 0x1c, "<I", MFT_RECORD_SIZE)
    _put(record, 0x30, "<H", 0xA55A)
    _put(record, 0x32, "<H", 0x1111)
    _put(record, 0x34, "<H", 0x2222)
    # Simulate on-disk USA words, then place the replacement values in the USA.
    _put(record, 510, "<H", 0xA55A)
    _put(record, 1022, "<H", 0xA55A)
    return bytes(record)


def _boot_sector() -> bytes:
    boot = bytearray(BPS)
    boot[3:11] = b"NTFS    "
    _put(boot, 0x0B, "<H", BPS)
    boot[0x0D] = SPC
    boot[0x15] = 0xF8
    _put(boot, 0x28, "<Q", TOTAL_SECTORS)
    _put(boot, 0x30, "<Q", MFT_LCN)
    _put(boot, 0x38, "<Q", MFT_MIRROR_LCN)
    _put(boot, 0x40, "<b", -10)
    _put(boot, 0x44, "<b", -10)
    boot[0x1FE:0x200] = b"\x55\xAA"
    return bytes(boot)


def _write_cluster(image: bytearray, lcn: int, data: bytes) -> None:
    start = lcn * CLUSTER
    if start < 0 or start + len(data) > len(image):
        raise ValueError(f"cluster {lcn} lies outside image")
    image[start:start + len(data)] = data


def _padded(data: bytes, size: int) -> bytes:
    return data[:size].ljust(size, b"\0")


def build_image() -> tuple[bytes, dict[str, object]]:
    image = bytearray(IMAGE_SIZE)
    boot = _boot_sector()
    image[:BPS] = boot
    image[(TOTAL_SECTORS - 1) * BPS:TOTAL_SECTORS * BPS] = boot

    # Bitmap bits are cluster allocation facts for the fixture, not claims
    # about whether deleted bytes still contain the original content.
    bitmap = bytearray((TOTAL_SECTORS + 7) // 8)

    def mark(lcn: int, count: int = 1) -> None:
        for cluster in range(lcn, lcn + count):
            bitmap[cluster // 8] |= 1 << (cluster & 7)

    mark(MFT_LCN, MFT_CLUSTERS)
    mark(300)
    mark(305)
    mark(310)
    mark(315)
    mark(321)  # deleted-reused.bin deliberately has mixed allocation
    mark(330)  # incomplete active file's one available cluster

    records: dict[int, bytes] = {}
    # Record 0 bootstraps the fragmented MFT region used by this image.
    records[0] = _file_record(
        0, 1, 1,
        [_nonresident_attr(0x80, [(MFT_LCN, MFT_CLUSTERS)],
                            MFT_CLUSTERS * CLUSTER, MFT_CLUSTERS * CLUSTER, 1)],
    )
    records[5] = _file_record(5, 1, 3, [])  # root directory
    records[6] = _file_record(6, 1, 1, [_resident_attr(0x80, bytes(bitmap), 1)])
    records[7] = _file_record(7, 1, 3, [_resident_attr(0x30, _filename_value("Documents", 5), 1)])
    records[8] = _file_record(8, 1, 3, [_resident_attr(0x30, _filename_value("Reports", 7), 1)])

    fragmented = b"ACTIVE-FRAGMENTED-FILE-" + bytes(range(32))
    fragmented = _padded(fragmented, 1024)
    records[9] = _file_record(
        9, 1, 1,
        [_resident_attr(0x30, _filename_value("fragmented.bin", 8, size=len(fragmented)), 1),
         _nonresident_attr(0x80, [(300, 1), (305, 1)], len(fragmented), len(fragmented), 2)],
    )
    _write_cluster(image, 300, fragmented[:512])
    _write_cluster(image, 305, fragmented[512:])

    resident = b"resident fixture\n"
    records[10] = _file_record(
        10, 1, 1,
        [_resident_attr(0x30, _filename_value("resident.txt", 7, size=len(resident)), 1),
         _resident_attr(0x80, resident, 2)],
    )

    sparse_expected = b"INITIALIZED-DATA".ljust(512, b"I") + b"\0" * 1024
    records[11] = _file_record(
        11, 1, 1,
        [_resident_attr(0x30, _filename_value("sparse-partial.bin", 7, size=1536), 1),
         _nonresident_attr(0x80, [(310, 1), (None, 1), (315, 1)], 1536, 512, 2)],
    )
    _write_cluster(image, 310, sparse_expected[:512])
    _write_cluster(image, 315, b"PHYSICAL-BUT-UNINITIALIZED".ljust(512, b"X"))

    deleted_free = _padded(b"DELETED-FREE-CONTENT", 512)
    records[12] = _file_record(
        12, 2, 0,
        [_resident_attr(0x30, _filename_value("deleted-free.txt", 7, 2, len(deleted_free)), 1),
         _nonresident_attr(0x80, [(320, 1)], len(deleted_free), len(deleted_free), 2)],
    )
    _write_cluster(image, 320, deleted_free)

    deleted_mixed = _padded(b"DELETED-MIXED-CONTENT", 1024)
    records[13] = _file_record(
        13, 2, 0,
        [_resident_attr(0x30, _filename_value("deleted-reused.bin", 8, 2, len(deleted_mixed)), 1),
         _nonresident_attr(0x80, [(321, 1), (322, 1)], len(deleted_mixed), len(deleted_mixed), 2)],
    )
    _write_cluster(image, 321, deleted_mixed[:512])
    _write_cluster(image, 322, deleted_mixed[512:])

    records[14] = _file_record(14, 1, 1, [], malformed=True)
    records[15] = _file_record(
        15, 1, 1,
        [_resident_attr(0x30, _filename_value("incomplete.bin", 7, size=1024), 1),
         _nonresident_attr(0x80, [(330, 1)], 1024, 1024, 2)],
    )
    _write_cluster(image, 330, b"ONLY-HALF-OF-STREAM".ljust(512, b"Q"))

    # Populate the MFT records and leave all other records zero-filled.
    for number, record in records.items():
        start = MFT_LCN * CLUSTER + number * MFT_RECORD_SIZE
        image[start:start + MFT_RECORD_SIZE] = record
    # Keep the four bootstrap records in the conventional mirror location so
    # candidate validation can exercise a credible $MFTMirr area as well.
    for number in range(4):
        record = records.get(number)
        if record is not None:
            start = MFT_MIRROR_LCN * CLUSTER + number * MFT_RECORD_SIZE
            image[start:start + MFT_RECORD_SIZE] = record

    expected = {
        "\\Documents\\Reports\\fragmented.bin": {
            "record": 9, "status": "recovered", "data": fragmented,
        },
        "\\Documents\\resident.txt": {
            "record": 10, "status": "recovered", "data": resident,
        },
        "\\Documents\\sparse-partial.bin": {
            "record": 11, "status": "recovered", "data": sparse_expected,
        },
        "\\Documents\\deleted-free.txt": {
            "record": 12, "status": "recovered", "data": deleted_free,
            "allocation_status": "unallocated",
        },
        "\\Documents\\Reports\\deleted-reused.bin": {
            "record": 13, "status": "skipped-allocation", "data": deleted_mixed,
            "allocation_status": "mixed",
        },
        "\\Documents\\incomplete.bin": {
            "record": 15, "status": "error", "data": None,
        },
    }
    manifest_files = []
    for path, item in expected.items():
        data = item["data"]
        row = {key: value for key, value in item.items() if key != "data"}
        row["path"] = path
        row["size"] = len(data) if data is not None else 1024
        row["sha256"] = hashlib.sha256(data).hexdigest() if data is not None else None
        manifest_files.append(row)
    manifest = {
        "format": "easeus-ntfs-recovery.synthetic-ntfs.v1",
        "geometry": {
            "offset_bytes": 0, "bytes_per_sector": BPS,
            "sectors_per_cluster": SPC, "total_sectors": TOTAL_SECTORS,
            "mft_lcn": MFT_LCN, "mft_record_size": MFT_RECORD_SIZE,
        },
        "image_size": IMAGE_SIZE,
        "files": manifest_files,
        "malformed_records": [14],
        "notes": [
            "deleted-reused.bin is mixed allocation and must be skipped by default",
            "incomplete.bin has a declared 1024-byte stream but only one physical cluster",
            "hashes describe expected output bytes, not proof of deleted-file provenance",
        ],
    }
    return bytes(image), manifest


def generate_image(image_path: str | Path, manifest_path: str | Path) -> dict[str, object]:
    image, manifest = build_image()
    image_path = Path(image_path)
    manifest_path = Path(manifest_path)
    image_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    image_path.write_bytes(image)
    manifest["image_sha256"] = hashlib.sha256(image).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    manifest = generate_image(args.image, args.manifest)
    print(json.dumps({"image": str(args.image), "manifest": str(args.manifest),
                      "image_size": manifest["image_size"],
                      "image_sha256": manifest["image_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
