"""Read-only NTFS recovery primitives.

The implementation follows the recovered DLL's observable pipeline: validate a
boot sector, locate MFT records, fix the NTFS update-sequence array, decode
attributes and data runs, then build names/parent relationships from FILE_NAME
attributes and directory indexes.  It never writes to the source image.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import io
import os
import json
import sys
import re
import struct
import uuid
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Mapping, Optional, Sequence


EASEUS_NTFS_SECTORS_PER_CLUSTER = frozenset(
    (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100)
)
EASEUS_NTFS_ZERO_FIELD_OFFSETS = (0x0e, 0x10, 0x11, 0x12, 0x13, 0x14,
                                  0x16, 0x17, 0x20, 0x21, 0x22, 0x23)

def u16(b: bytes, o: int) -> int: return struct.unpack_from("<H", b, o)[0]
def u32(b: bytes, o: int) -> int: return struct.unpack_from("<I", b, o)[0]
def u64(b: bytes, o: int) -> int: return struct.unpack_from("<Q", b, o)[0]
def s8(b: bytes, o: int) -> int: return struct.unpack_from("<b", b, o)[0]
def s16(b: bytes, o: int) -> int: return struct.unpack_from("<h", b, o)[0]
def s64(b: bytes, o: int) -> int: return struct.unpack_from("<q", b, o)[0]


class VHDXError(ValueError):
    """Malformed, unsupported, or out-of-bounds VHDX metadata."""


class VHDXReader:
    """Read-only random-access view of a dynamically expanding VHDX image.

    The reader exposes the small file-like interface used by ``NTFSVolume``.
    It validates VHDX headers, region tables, metadata, BAT bounds, and block
    states, and translates only requested virtual ranges.  Unallocated and
    zero/undefined blocks read as zeroes.  Partially present blocks consult the
    VHDX sector bitmap one logical sector at a time.
    """

    VHDX_HEADER_OFFSET = (0x10000, 0x20000)
    VHDX_HEADER_SIZE = 0x1000
    VHDX_REGION_OFFSET = (0x30000, 0x40000)
    VHDX_REGION_SIZE = 0x10000
    FILE_IDENTIFIER = b"vhdxfile"
    HEADER_SIGNATURE = b"head"
    REGION_SIGNATURE = b"regi"
    METADATA_SIGNATURE = b"metadata"
    BLOCK_SIZE_DEFAULT = 32 * 1024 * 1024

    BAT_GUID = uuid.UUID("2dc27766-f623-4200-9d64-115e9bfd4a08")
    METADATA_GUID = uuid.UUID("8b7ca206-4790-4b9a-b8fe-575f050f886e")
    FILE_PARAMETERS_GUID = uuid.UUID("caa16737-fa36-4d43-b3b6-33f0aa44e76b")
    VIRTUAL_SIZE_GUID = uuid.UUID("2fa54224-cd1b-4876-b211-5dbed83bf4b8")
    LOGICAL_SECTOR_GUID = uuid.UUID("8141bf1d-a96f-4709-ba47-f233a8faab5f")
    PHYSICAL_SECTOR_GUID = uuid.UUID("cda348c7-445d-4471-9cc9-e9885251c556")

    # VHDX payload BAT states.  States 0-3 represent absent/zero data.
    _ZERO_STATES = frozenset((0, 1, 2, 3))
    _FULLY_PRESENT = 6
    _PARTIALLY_PRESENT = 7

    def __init__(self, source: str | Path | BinaryIO):
        self._owned = not hasattr(source, "read")
        self.f = open(source, "rb") if self._owned else source  # type: ignore[arg-type]
        self._position = 0
        try:
            self._host_size = self._file_size()
            if self._host_size < 0x50000:
                raise VHDXError("VHDX file is too small")
            if self._read_raw(0, 8) != self.FILE_IDENTIFIER:
                raise VHDXError("invalid VHDX file identifier")
            self._parse_headers()
            self._parse_regions()
            self._parse_metadata()
            self._parse_bat()
        except Exception:
            if self._owned:
                self.f.close()
            raise

    def _file_size(self) -> int:
        current = self.f.tell()
        self.f.seek(0, os.SEEK_END)
        size = self.f.tell()
        self.f.seek(current)
        return size

    def _read_raw(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self._host_size:
            raise VHDXError("VHDX metadata read is outside the host file")
        self.f.seek(offset)
        value = self.f.read(length)
        if len(value) != length:
            raise VHDXError("short VHDX metadata read")
        return value

    @staticmethod
    def _crc32c(data: bytes) -> int:
        crc = 0xffffffff
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
        return crc ^ 0xffffffff

    @classmethod
    def _valid_checksum(cls, raw: bytes, checksum_offset: int) -> bool:
        if checksum_offset + 4 > len(raw):
            return False
        expected = u32(raw, checksum_offset)
        copy = bytearray(raw)
        copy[checksum_offset:checksum_offset + 4] = b"\0\0\0\0"
        return cls._crc32c(bytes(copy)) == expected

    def _parse_headers(self) -> None:
        valid: list[tuple[int, bytes]] = []
        for offset in self.VHDX_HEADER_OFFSET:
            raw = self._read_raw(offset, self.VHDX_HEADER_SIZE)
            if raw[:4] == self.HEADER_SIGNATURE and self._valid_checksum(raw, 4):
                valid.append((u64(raw, 8), raw))
        if not valid:
            raise VHDXError("no valid VHDX header copy")
        self.header_sequence, self.header = max(valid, key=lambda item: item[0])

    def _parse_regions(self) -> None:
        tables: list[dict[uuid.UUID, tuple[int, int, int]]] = []
        for offset in self.VHDX_REGION_OFFSET:
            raw = self._read_raw(offset, self.VHDX_REGION_SIZE)
            if raw[:4] != self.REGION_SIGNATURE or not self._valid_checksum(raw, 4):
                continue
            count = u32(raw, 8)
            if count > (self.VHDX_REGION_SIZE - 0x20) // 32:
                continue
            entries: dict[uuid.UUID, tuple[int, int, int]] = {}
            valid = True
            for index in range(count):
                pos = 0x10 + index * 32
                identifier = uuid.UUID(bytes_le=raw[pos:pos + 16])
                region_offset, region_length, flags = u64(raw, pos + 16), u32(raw, pos + 24), u32(raw, pos + 28)
                if region_offset % 0x100000 or not region_length or region_offset + region_length > self._host_size:
                    valid = False
                    break
                entries[identifier] = (region_offset, region_length, flags)
            if valid:
                tables.append(entries)
        if not tables:
            raise VHDXError("no valid VHDX region table")
        self.regions = max(tables, key=lambda table: len(table))
        if self.BAT_GUID not in self.regions or self.METADATA_GUID not in self.regions:
            raise VHDXError("VHDX BAT or metadata region is missing")
        self.bat_offset, self.bat_length, _ = self.regions[self.BAT_GUID]
        self.metadata_offset, self.metadata_length, _ = self.regions[self.METADATA_GUID]

    def _parse_metadata(self) -> None:
        raw = self._read_raw(self.metadata_offset, self.metadata_length)
        if raw[:8] != self.METADATA_SIGNATURE:
            raise VHDXError("invalid VHDX metadata signature")
        # Metadata header: signature, 16-bit entry count at 0x0a, then
        # reserved bytes; metadata item descriptors begin at 0x20.
        count = u16(raw, 0x0a)
        if count > (len(raw) - 0x20) // 32:
            raise VHDXError("invalid VHDX metadata entry count")
        entries: dict[uuid.UUID, tuple[int, int, int]] = {}
        for index in range(count):
            pos = 0x20 + index * 32
            identifier = uuid.UUID(bytes_le=raw[pos:pos + 16])
            relative_offset, length, flags = u32(raw, pos + 16), u32(raw, pos + 20), u32(raw, pos + 24)
            if relative_offset + length > len(raw) or relative_offset < 0x20 or not length:
                raise VHDXError("VHDX metadata item is outside metadata region")
            entries[identifier] = (relative_offset, length, flags)
        required = (self.FILE_PARAMETERS_GUID, self.VIRTUAL_SIZE_GUID,
                    self.LOGICAL_SECTOR_GUID, self.PHYSICAL_SECTOR_GUID)
        if any(identifier not in entries for identifier in required):
            raise VHDXError("required VHDX metadata item is missing")
        self.metadata = {
            identifier: raw[offset:offset + length]
            for identifier, (offset, length, _flags) in entries.items()
        }
        self.virtual_size = u64(self.metadata[self.VIRTUAL_SIZE_GUID], 0)
        file_parameters = self.metadata[self.FILE_PARAMETERS_GUID]
        if len(file_parameters) < 8:
            raise VHDXError("short VHDX file parameters metadata")
        self.block_size = u32(file_parameters, 0)
        self.logical_sector_size = u32(self.metadata[self.LOGICAL_SECTOR_GUID], 0)
        self.physical_sector_size = u32(self.metadata[self.PHYSICAL_SECTOR_GUID], 0)
        if not self.virtual_size or self.virtual_size % self.logical_sector_size:
            raise VHDXError("invalid VHDX virtual size")
        if self.logical_sector_size not in (512, 4096) or self.physical_sector_size not in (512, 4096):
            raise VHDXError("unsupported VHDX sector size")
        if self.block_size < 1024 * 1024 or self.block_size > 256 * 1024 * 1024 or self.block_size & (self.block_size - 1):
            raise VHDXError("unsupported VHDX block size")
        if self.block_size % self.logical_sector_size:
            raise VHDXError("VHDX block size is not sector aligned")
        self._sectors_per_block = self.block_size // self.logical_sector_size
        self._blocks_per_chunk = (2 * 1024 * 1024 * 1024) // self.block_size
        if self._blocks_per_chunk <= 0:
            raise VHDXError("invalid VHDX chunk geometry")

    def _parse_bat(self) -> None:
        required_entries = ((self.virtual_size + self.block_size - 1) // self.block_size)
        chunks = (required_entries + self._blocks_per_chunk - 1) // self._blocks_per_chunk
        # Each 2 GiB chunk consumes one BAT slot for every possible payload
        # block plus one sector-bitmap slot, including unused tail slots.
        self._bat_entries_needed = chunks * (self._blocks_per_chunk + 1)
        if self._bat_entries_needed * 8 > self.bat_length:
            raise VHDXError("VHDX BAT region is too small")
        raw = self._read_raw(self.bat_offset, self._bat_entries_needed * 8)
        self._bat = [u64(raw, index * 8) for index in range(self._bat_entries_needed)]
        for entry in self._bat:
            state = entry & 0x7
            if state not in self._ZERO_STATES and state not in (self._FULLY_PRESENT, self._PARTIALLY_PRESENT):
                raise VHDXError(f"unsupported VHDX BAT state {state}")
            if state in (self._FULLY_PRESENT, self._PARTIALLY_PRESENT):
                offset = entry & ~0x7
                if offset % 0x100000 or offset >= self._host_size:
                    raise VHDXError("VHDX BAT payload offset is invalid")

    @property
    def size(self) -> int:
        return self.virtual_size

    def _bat_entry(self, block_number: int) -> int:
        chunk = block_number // self._blocks_per_chunk
        within = block_number % self._blocks_per_chunk
        return self._bat[chunk * (self._blocks_per_chunk + 1) + within]

    def _bitmap_entry(self, block_number: int) -> int:
        chunk = block_number // self._blocks_per_chunk
        return self._bat[chunk * (self._blocks_per_chunk + 1) + self._blocks_per_chunk]

    def _sector_present(self, block_number: int, sector_number: int) -> bool:
        bitmap = self._bitmap_entry(block_number)
        state = bitmap & 0x7
        if state in self._ZERO_STATES:
            return False
        if state != self._FULLY_PRESENT:
            raise VHDXError("unsupported VHDX sector bitmap BAT state")
        offset = (bitmap & ~0x7) + sector_number // 8
        if offset >= self._host_size:
            raise VHDXError("VHDX sector bitmap lies outside host file")
        return bool(self._read_raw(offset, 1)[0] & (1 << (sector_number & 7)))

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("negative VHDX read range")
        if offset > self.virtual_size:
            raise ValueError("VHDX read starts beyond virtual disk")
        length = min(length, self.virtual_size - offset)
        output = bytearray()
        while length:
            sector = offset // self.logical_sector_size
            within_sector = offset % self.logical_sector_size
            take = min(length, self.logical_sector_size - within_sector)
            block = (sector * self.logical_sector_size) // self.block_size
            sector_in_block = sector % self._sectors_per_block
            entry = self._bat_entry(block)
            state = entry & 0x7
            if state in self._ZERO_STATES or (state == self._PARTIALLY_PRESENT and not self._sector_present(block, sector_in_block)):
                output.extend(b"\0" * take)
            elif state in (self._FULLY_PRESENT, self._PARTIALLY_PRESENT):
                physical = (entry & ~0x7) + sector_in_block * self.logical_sector_size + within_sector
                output.extend(self._read_raw(physical, take))
            else:
                raise VHDXError("unsupported VHDX BAT payload state")
            offset += take
            length -= take
        return bytes(output)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self.virtual_size + offset
        else:
            raise ValueError("invalid VHDX seek mode")
        if position < 0:
            raise ValueError("negative VHDX seek")
        self._position = position
        return position

    def tell(self) -> int:
        return self._position

    def read(self, length: int = -1) -> bytes:
        if length is None or length < 0:
            length = self.virtual_size - self._position
        data = self.read_at(self._position, length)
        self._position += len(data)
        return data

    def close(self) -> None:
        if self._owned:
            self.f.close()

    def __enter__(self) -> "VHDXReader":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclasses.dataclass(frozen=True)
class DataRun:
    lcn: Optional[int]
    length: int
    vcn: int


@dataclasses.dataclass(frozen=True)
class AllocationAssessment:
    """Conservative evidence about the current allocation of DATA runs.

    ``allocated`` means that at least one referenced cluster is currently set
    in ``$Bitmap``; it does not prove overwrite or ownership.  ``unallocated``
    likewise does not prove that the original bytes remain intact.
    """
    status: str
    allocated_clusters: int = 0
    unallocated_clusters: int = 0
    sparse_clusters: int = 0
    checked_clusters: int = 0
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "allocated_clusters": self.allocated_clusters,
            "unallocated_clusters": self.unallocated_clusters,
            "sparse_clusters": self.sparse_clusters,
            "checked_clusters": self.checked_clusters,
            "warnings": list(self.warnings),
        }


def decode_data_runs(data: bytes, start_vcn: int = 0) -> list[DataRun]:
    """Decode NTFS mapping pairs; sparse runs have lcn=None."""
    out: list[DataRun] = []
    i = 0
    vcn = start_vcn
    lcn = 0
    while i < len(data):
        head = data[i]
        i += 1
        if head == 0:
            break
        nlen, noff = head & 0x0f, head >> 4
        if not nlen or i + nlen + noff > len(data):
            raise ValueError("truncated or invalid NTFS mapping pair")
        length = int.from_bytes(data[i:i+nlen], "little", signed=False)
        i += nlen
        if noff:
            delta = int.from_bytes(data[i:i+noff], "little", signed=bool(data[i+noff-1] & 0x80))
            lcn += delta
            run_lcn: Optional[int] = lcn
        else:
            run_lcn = None
        i += noff
        if length <= 0:
            raise ValueError("zero-length NTFS run")
        out.append(DataRun(run_lcn, length, vcn))
        vcn += length
    return out


def apply_fixup(record: bytes, sector_size: int = 512) -> bytes:
    """Validate/replace the USA words in an NTFS multi-sector record."""
    if len(record) < 8:
        raise ValueError("short NTFS record")
    usa_off, usa_count = u16(record, 4), u16(record, 6)
    if usa_count < 1 or usa_off + usa_count * 2 > len(record):
        raise ValueError("invalid update sequence array")
    sectors = (len(record) + sector_size - 1) // sector_size
    if usa_count != sectors + 1:
        raise ValueError("update sequence count does not match record sectors")
    seq = record[usa_off:usa_off+2]
    out = bytearray(record)
    for n in range(sectors):
        end = min((n + 1) * sector_size, len(out))
        pos = end - 2
        if bytes(out[pos:end]) != seq:
            raise ValueError("NTFS update sequence mismatch")
        out[pos:end] = record[usa_off + 2 + n*2:usa_off + 4 + n*2]
    return bytes(out)


@dataclasses.dataclass
class VolumeGeometry:
    bytes_per_sector: int
    sectors_per_cluster: int
    total_sectors: int
    mft_lcn: int
    mftmirr_lcn: int
    clusters_per_record: int
    clusters_per_index: int

    @property
    def cluster_size(self) -> int: return self.bytes_per_sector * self.sectors_per_cluster
    @property
    def record_size(self) -> int:
        return (1 << -self.clusters_per_record) if self.clusters_per_record < 0 else self.clusters_per_record * self.cluster_size
    @property
    def index_size(self) -> int:
        return (1 << -self.clusters_per_index) if self.clusters_per_index < 0 else self.clusters_per_index * self.cluster_size

    @classmethod
    def from_boot_sector(cls, boot: bytes) -> "VolumeGeometry":
        if not is_easeus_ntfs_boot_sector(boot):
            raise ValueError("not an NTFS boot sector")
        bps, spc = u16(boot, 0x0b), boot[0x0d]
        # EaseUS accepts any nonzero 0x200-aligned BPS value, but the recovery
        # engine keeps its existing safety restriction to standard NTFS sizes.
        if bps not in (512, 1024, 2048, 4096) or spc not in EASEUS_NTFS_SECTORS_PER_CLUSTER:
            raise ValueError("invalid NTFS geometry")
        total, mft, mirror = u64(boot, 0x28), u64(boot, 0x30), u64(boot, 0x38)
        if not total or mft >= total or mirror >= total:
            raise ValueError("NTFS geometry lies outside the volume")
        geo = cls(bps, spc, total, mft, mirror, s8(boot, 0x40), s8(boot, 0x44))
        if geo.record_size < 0x400 or geo.record_size > 0x1000 or geo.index_size < 0x400:
            raise ValueError("unsupported NTFS record or index size")
        return geo


def is_easeus_ntfs_boot_sector(boot: bytes) -> bool:
    """Mirror the structural predicate in FUN_180016970.

    That routine copies 0x200 bytes, checks the OEM name, accepts only the
    documented NTFS sector-size/cluster-size values, rejects legacy FAT BPB
    fields, and requires the 0x55AA signature.  It is deliberately separate
    from geometry construction so callers can cheaply probe sector offsets.
    """
    if len(boot) < 0x200 or boot[3:11] != b"NTFS    ":
        return False
    bps, spc = u16(boot, 0x0b), boot[0x0d]
    if not bps or bps & 0x1ff or spc not in (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100):
        return False
    # FUN_180016970 checks these legacy BPB fields individually.  It does not
    # reject the media byte at 0x15, which is commonly 0xF8 on NTFS volumes.
    if any(boot[o] for o in EASEUS_NTFS_ZERO_FIELD_OFFSETS):
        return False
    return boot[0x1fe:0x200] == b"\x55\xaa"


@dataclasses.dataclass
class NTFSCandidate:
    """A partition candidate produced by the boot/DBR discovery stage."""
    offset: int
    geometry: VolumeGeometry
    boot_sector: bytes
    backup_offset: Optional[int] = None
    backup_matches: bool = False
    mft_record_readable: bool = False
    mft_runs_readable: bool = False
    source_kind: str = "primary"
    mode: int = 1
    length_bytes: int = 0
    mftmirr_lcn: int = 0
    flags: int = 0
    notes: list[str] = dataclasses.field(default_factory=list)

    @property
    def volume_bytes(self) -> int:
        return self.geometry.total_sectors * self.geometry.bytes_per_sector

    @property
    def mft_offset(self) -> int:
        return self.offset + self.geometry.mft_lcn * self.geometry.cluster_size

    @property
    def extent_sectors(self) -> int:
        return self.length_bytes // self.geometry.bytes_per_sector

    @property
    def easeus_duplicate_key(self) -> tuple[int, int]:
        """The two fields compared by EaseUS's IsBackupDBR path."""
        return self.length_bytes, self.mftmirr_lcn


class _SecureDestination:
    """Descriptor-relative destination root for filesystem-backed recovery."""
    def __init__(self, path: str | Path, source_stat: os.stat_result):
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise OSError("secure destination operations are unavailable")
        requested = Path(path).expanduser()
        if not requested.is_absolute():
            requested = Path.cwd() / requested
        self._reject_symlink_components(requested)
        self.path = requested.resolve()
        self.path.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        self.fd = os.open(self.path, flags)
        destination_stat = os.fstat(self.fd)
        if destination_stat.st_dev == source_stat.st_dev:
            os.close(self.fd)
            raise ValueError("recovery destination must be on a different filesystem")
        if (destination_stat.st_dev, destination_stat.st_ino) == (source_stat.st_dev, source_stat.st_ino):
            os.close(self.fd)
            raise ValueError("recovery destination must differ from source")

    @staticmethod
    def _reject_symlink_components(path: Path) -> None:
        current = Path(path.anchor) if path.is_absolute() else Path.cwd()
        for component in path.parts[1:] if path.is_absolute() else path.parts:
            current /= component
            try:
                if current.is_symlink():
                    raise ValueError(f"destination contains symlink component: {current}")
            except OSError as exc:
                raise OSError(f"cannot inspect destination component {current}") from exc

    def _open_dir_components(self, components: Sequence[str]) -> int:
        current = os.dup(self.fd)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            for component in components:
                if component in {"", ".", ".."} or os.sep in component or component == os.altsep:
                    raise ValueError("unsafe destination path component")
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = next_fd
            return current
        except Exception:
            os.close(current)
            raise

    def mkdir(self, components: Sequence[str]) -> Path:
        fd = self._open_dir_components(components)
        os.close(fd)
        return self.path.joinpath(*components)

    def create_file(self, components: Sequence[str], reserved: set[str]) -> tuple[Path, object]:
        if not components:
            raise ValueError("empty destination file path")
        parent_fd = self._open_dir_components(components[:-1])
        name = components[-1]
        stem, suffix = Path(name).stem, Path(name).suffix
        try:
            for index in range(0, 1_000_000):
                candidate_name = name if index == 0 else f"{stem} ({index}){suffix}"
                candidate = self.path.joinpath(*components[:-1], candidate_name)
                if str(candidate) in reserved:
                    continue
                try:
                    fd = os.open(candidate_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                  os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                reserved.add(str(candidate))
                return candidate, os.fdopen(fd, "wb")
            raise FileExistsError("unable to allocate a unique recovery filename")
        finally:
            os.close(parent_fd)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _relative_components(self, path: str | Path) -> list[str]:
        requested = Path(path).expanduser()
        if not requested.is_absolute():
            requested = Path.cwd() / requested
        self._reject_symlink_components(requested)
        resolved = requested.resolve()
        try:
            relative = resolved.relative_to(self.path)
        except ValueError as exc:
            raise ValueError("recovery log must be inside the secure destination") from exc
        components = list(relative.parts)
        if not components or any(component in {"", ".", ".."} for component in components):
            raise ValueError("unsafe recovery log path")
        return components

    def open_exclusive(self, path: str | Path) -> tuple[Path, object]:
        """Open a destination-relative file without following links or overwriting."""
        components = self._relative_components(path)
        parent_fd = self._open_dir_components(components[:-1])
        try:
            fd = os.open(components[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
            return self.path.joinpath(*components), os.fdopen(fd, "w", encoding="utf-8")
        finally:
            os.close(parent_fd)


def _source_size(source: BinaryIO | str | Path) -> int:
    """Return a seekable source size without changing the caller's position."""
    owned = not hasattr(source, "read")
    f = open(source, "rb") if owned else source  # type: ignore[arg-type]
    try:
        position = f.tell()
        f.seek(0, io.SEEK_END)
        size = f.tell()
        f.seek(position)
        return size
    finally:
        if owned:
            f.close()


def _clamped_easeus_extent(source: BinaryIO | str | Path, offset: int,
                           geometry: VolumeGeometry,
                           storage_sector_size: Optional[int] = None) -> int:
    """Apply EaseUS's device-boundary and eight-sector extent rules."""
    if offset < 0:
        raise ValueError("negative candidate start")
    storage_bps = storage_sector_size or geometry.bytes_per_sector
    if storage_bps <= 0:
        raise ValueError("invalid storage sector size")
    available = max(0, _source_size(source) - offset)
    extent = min(geometry.total_sectors * geometry.bytes_per_sector, available)
    extent -= extent % storage_bps
    if extent < 8 * storage_bps:
        raise ValueError("candidate extent is smaller than eight storage sectors")
    return extent


def _candidate_from_boot(source: BinaryIO | str | Path, offset: int,
                         boot: bytes, *, source_kind: str, mode: int,
                         storage_sector_size: Optional[int] = None,
                         backup_offset: Optional[int] = None) -> NTFSCandidate:
    geometry = VolumeGeometry.from_boot_sector(boot)
    length_bytes = _clamped_easeus_extent(source, offset, geometry, storage_sector_size)
    return NTFSCandidate(
        offset=offset,
        geometry=geometry,
        boot_sector=boot,
        backup_offset=backup_offset,
        source_kind=source_kind,
        mode=mode,
        length_bytes=length_bytes,
        # EaseUS's candidate duplicate key uses the field it reads at DBR
        # offset 0x48, independently of the standard NTFS BPB geometry field
        # at 0x38 used by VolumeGeometry.
        mftmirr_lcn=u64(boot, 0x48),
    )


def derive_backup_ntfs_candidate(source: BinaryIO | str | Path,
                                 current_sector: int,
                                 storage_sector_size: int = 512) -> NTFSCandidate:
    """Build EaseUS's mode-2 candidate from a DBR found at current_sector.

    This is a targeted operation: it reads only the supplied DBR sector and
    performs no physical-device scan.  The candidate's inferred start is
    ``current_sector - DBR.total_sectors`` in storage-sector units.
    """
    if current_sector < 0 or storage_sector_size <= 0:
        raise ValueError("invalid backup DBR sector or storage sector size")
    current_offset = current_sector * storage_sector_size
    boot = _read_at(source, current_offset, 512)
    if not is_easeus_ntfs_boot_sector(boot):
        raise ValueError("backup DBR is not EaseUS-valid NTFS")
    geometry = VolumeGeometry.from_boot_sector(boot)
    start_sector = current_sector - geometry.total_sectors
    if start_sector < 0:
        raise ValueError("backup-derived candidate start is negative")
    start_offset = start_sector * storage_sector_size
    candidate = _candidate_from_boot(
        source, start_offset, boot, source_kind="backup", mode=2,
        storage_sector_size=storage_sector_size, backup_offset=current_offset,
    )
    candidate.notes.append("backup-derived start from current sector minus total sectors")
    return candidate


def easeus_candidates_duplicate(existing: NTFSCandidate,
                                proposed: NTFSCandidate) -> bool:
    """Mirror 0x18001fc30 plus the existing bit-0 flag shortcut."""
    return bool(existing.flags & 1) or existing.easeus_duplicate_key == proposed.easeus_duplicate_key


def update_zero_length_candidate_extents(existing: Iterable[NTFSCandidate],
                                         proposed: NTFSCandidate) -> int:
    """Mirror AdjustPartitionSizeAccordingtoDBR (0x18001fe60)."""
    updated = 0
    for candidate in existing:
        if candidate.length_bytes == 0:
            candidate.length_bytes = proposed.length_bytes
            updated += 1
    return updated


def _read_at(source: BinaryIO | str | Path, offset: int, size: int) -> bytes:
    owned = not hasattr(source, "read")
    f = open(source, "rb") if owned else source  # type: ignore[arg-type]
    try:
        f.seek(offset)
        return f.read(size)
    finally:
        if owned:
            f.close()


def validate_ntfs_candidate(source: BinaryIO | str | Path, offset: int) -> NTFSCandidate:
    """Validate one caller-supplied physical offset without scanning a device."""
    if offset < 0:
        raise ValueError("negative candidate offset")
    boot = _read_at(source, offset, 512)
    if not is_easeus_ntfs_boot_sector(boot):
        raise ValueError(f"offset {offset:#x} is not an EaseUS-valid NTFS DBR")
    candidate = _candidate_from_boot(source, offset, boot, source_kind="primary", mode=1)
    geometry = candidate.geometry
    candidate.backup_offset = offset + (geometry.total_sectors - 1) * geometry.bytes_per_sector
    backup = _read_at(source, candidate.backup_offset, 512)
    candidate.backup_matches = (
        is_easeus_ntfs_boot_sector(backup)
        and backup[0x0b:0x40] == boot[0x0b:0x40]
        and backup[0x40:0x48] == boot[0x40:0x48]
        and backup[0x48:0x50] == boot[0x48:0x50]
    )
    candidate.notes.append("backup DBR geometry matches" if candidate.backup_matches else "backup DBR absent or geometry differs")
    with NTFSVolume(source, offset=offset) as volume:
        try:
            record0 = volume._record0()
            candidate.mft_record_readable = record0.number == 0 and bool(record0.attrs)
            candidate.mft_runs_readable = bool(volume.mft_runs())
            candidate.notes.append("$MFT record 0 and mapping pairs readable")
        except (ValueError, struct.error, OSError) as exc:
            candidate.notes.append(f"MFT unreadable: {exc}")
    return candidate


def discover_ntfs_candidates(source: BinaryIO | str | Path, offsets: Sequence[int]) -> list[NTFSCandidate]:
    """Validate known/provided DBR offsets; never performs an implicit disk scan."""
    found: list[NTFSCandidate] = []
    seen: set[int] = set()
    for offset in offsets:
        if offset in seen:
            continue
        seen.add(offset)
        try:
            found.append(validate_ntfs_candidate(source, offset))
        except (ValueError, OSError, struct.error):
            continue
    return found


@dataclasses.dataclass
class Attribute:
    type: int
    name: str
    flags: int
    instance: int
    resident: bool
    value: bytes = b""
    runs: list[DataRun] = dataclasses.field(default_factory=list)
    data_size: int = 0
    initialized_size: int = 0
    lowest_vcn: int = 0
    highest_vcn: int = 0

    @property
    def nonresident(self) -> bool: return not self.resident


def parse_attributes(record: bytes, record_size: Optional[int] = None) -> list[Attribute]:
    end = min(record_size or len(record), len(record))
    pos = u16(record, 0x14)
    attrs: list[Attribute] = []
    while pos + 8 <= end:
        typ, length = u32(record, pos), u32(record, pos + 4)
        if typ == 0xffffffff: break
        if length < 0x18 or pos + length > end:
            raise ValueError("invalid NTFS attribute length")
        nonres = record[pos + 8] != 0
        name_len, name_off = record[pos + 9], u16(record, pos + 10)
        name = record[pos+name_off:pos+name_off+name_len*2].decode("utf-16le", "replace") if name_len else ""
        flags, inst = u16(record, pos+12), u16(record, pos+14)
        if not nonres:
            voff, vlen = u16(record, pos+20), u32(record, pos+16)
            value = record[pos+voff:pos+voff+vlen]
            attrs.append(Attribute(typ, name, flags, inst, True, value=value))
        else:
            low, high = s64(record, pos+16), s64(record, pos+24)
            roff = u16(record, pos+32)
            runs = decode_data_runs(record[pos+roff:pos+length], low)
            attrs.append(Attribute(typ, name, flags, inst, False, runs=runs,
                                   data_size=u64(record, pos+48), initialized_size=u64(record, pos+56),
                                   lowest_vcn=low, highest_vcn=high))
        pos += length
    return attrs


@dataclasses.dataclass
class FileName:
    parent: int
    name: str
    namespace: int
    allocated_size: int
    real_size: int
    flags: int
    parent_sequence: int = 0


@dataclasses.dataclass
class FileRecord:
    number: int
    raw: bytes
    sequence: int
    flags: int
    attrs: list[Attribute]
    names: list[FileName]

    @property
    def in_use(self) -> bool: return bool(self.flags & 1)
    @property
    def is_directory(self) -> bool: return bool(self.flags & 2)


@dataclasses.dataclass(frozen=True)
class DeletedFileDiscovery:
    """A structurally valid deleted FILE record found independently of indexes.

    Discovery deliberately stops at metadata and allocation evidence.  It does
    not imply that the referenced bytes are original or that extraction is
    safe; callers must still use the normal recovery API.
    """
    record: FileRecord
    data: Attribute
    allocation: AllocationAssessment


@dataclasses.dataclass(frozen=True)
class RawFileObservation:
    """A validated FILE record found without assigning it to a volume.

    ``record_number`` is normally unknown outside an MFT context; NTFS stores
    the record number in the MFT position, not in the FILE header itself.
    ``offset`` and ``sector`` are absolute source coordinates.
    """
    offset: int
    sector: int
    record_number: Optional[int]
    sequence: int
    flags: int
    record_size: int
    names: tuple[FileName, ...]
    special_name: Optional[str]
    validation_status: str
    record: FileRecord


@dataclasses.dataclass
class DirectoryEntry:
    file_reference: int
    key: Optional[FileName]
    child_vcn: Optional[int] = None
    end: bool = False
    sequence: int = 0


@dataclasses.dataclass(frozen=True)
class AttributeListEntry:
    type: int
    lowest_vcn: int
    file_reference: int
    sequence: int
    instance: int
    name: str


def parse_attribute_list(value: bytes) -> list[AttributeListEntry]:
    """Parse resident/nonresident $ATTRIBUTE_LIST entry records."""
    entries: list[AttributeListEntry] = []
    pos = 0
    while pos + 0x1a <= len(value):
        typ, length = u32(value, pos), u16(value, pos + 4)
        if typ == 0xffffffff:
            break
        if length < 0x1a or pos + length > len(value):
            break
        name_len, name_off = value[pos + 6], value[pos + 7]
        if name_off + name_len * 2 > length:
            break
        name = value[pos + name_off:pos + name_off + name_len * 2].decode("utf-16le", "replace")
        reference = u64(value, pos + 0x10)
        entries.append(AttributeListEntry(
            typ, u64(value, pos + 8), reference & ((1 << 48) - 1),
            reference >> 48, u16(value, pos + 0x18), name,
        ))
        pos += length
    return entries


def parse_index_entries(buf: bytes, base: int = 0) -> list[DirectoryEntry]:
    """Parse an INDEX_ROOT value or an INDX buffer's index header."""
    if len(buf) < base + 0x20:
        return []
    # For INDEX_ROOT, the index header starts at value+8.  For INDX it starts
    # at buffer+0x18.  Callers can pass the header offset explicitly.
    h = base
    entries_off, total = u32(buf, h + 0x10), u32(buf, h + 0x14)
    pos, limit = h + entries_off, min(h + total, len(buf))
    result: list[DirectoryEntry] = []
    while pos + 0x10 <= limit:
        ref, length, key_len, flags = u64(buf, pos), u16(buf, pos+8), u16(buf, pos+10), u32(buf, pos+12)
        if length < 0x10 or pos + length > limit: break
        end = bool(flags & 2)
        key = None
        if key_len and pos + 0x10 + key_len <= pos + length:
            try: key = parse_file_name(buf[pos+0x10:pos+0x10+key_len])
            except (ValueError, struct.error): pass
        child = u64(buf, pos + length - 8) if flags & 1 and length >= 0x18 else None
        result.append(DirectoryEntry(ref & ((1 << 48) - 1), key, child, end, ref >> 48))
        pos += length
        if end: break
    return result


def parse_file_name(value: bytes) -> FileName:
    if len(value) < 0x42: raise ValueError("short FILE_NAME value")
    parent_ref = u64(value, 0)
    parent = parent_ref & ((1 << 48) - 1)
    name_len, namespace = value[0x40], value[0x41]
    name = value[0x42:0x42+name_len*2].decode("utf-16le", "replace")
    return FileName(parent, name, namespace, u64(value, 0x28), u64(value, 0x30),
                    u32(value, 0x38), parent_ref >> 48)


def parse_file_record(raw: bytes, number: int = -1, sector_size: int = 512) -> FileRecord:
    fixed = apply_fixup(raw, sector_size)
    if fixed[:4] != b"FILE": raise ValueError("not a FILE record")
    attrs = parse_attributes(fixed, len(fixed))
    names = [parse_file_name(a.value) for a in attrs if a.type == 0x30 and a.resident]
    return FileRecord(number, fixed, u16(fixed, 0x10), u16(fixed, 0x16), attrs, names)


def _raw_file_record_size(window: bytes) -> Optional[int]:
    """Apply the confirmed EaseUS FILE-header/size checks to a raw window."""
    if len(window) < 0x400 or window[:4] != b"FILE":
        return None
    usa_count = u16(window, 0x06)
    record_size = u32(window, 0x1c)
    usa_offset = u16(window, 0x04)
    if usa_count >= 0x11 or not record_size or record_size >= 0x1001:
        return None
    if record_size % 0x400 or record_size // 0x200 < usa_count - 1:
        return None
    if usa_offset < 0x2a or usa_offset >= 0x101:
        return None
    return record_size


def iter_raw_file_records(
    source: BinaryIO | str | Path,
    start_sector: int,
    sector_count: int,
    storage_sector_size: int = 512,
    *,
    chunk_sectors: int = 16,
) -> Iterator[RawFileObservation]:
    """Yield validated FILE records from an explicit bounded source range.

    The iterator examines only storage-sector starts in
    ``[start_sector, start_sector + sector_count)``. Reads are bounded to that
    range and use a 16-sector prefix/suffix overlap so a record or fragment at
    a chunk boundary can be validated without loading the complete scan into
    memory. The 16-sector processing window is look-ahead; the scan increment
    remains exactly one storage sector.

    Observations are intentionally not attached to ``NTFSVolume`` or any
    partition. A raw FILE header does not contain its MFT record number, so
    ``record_number`` is ``None`` until MFT geometry or another independent
    identity source is available. Malformed or truncated candidates are
    skipped, while valid observations contain their parsed FILE record and
    FILE_NAME metadata. Repeated observations at the same physical offset are
    emitted once; no unconfirmed EaseUS duplicate key is applied.
    """
    if start_sector < 0 or sector_count <= 0:
        raise ValueError("invalid raw FILE discovery range")
    if storage_sector_size < 8:
        raise ValueError("storage sector size must be at least eight bytes")
    if chunk_sectors <= 0:
        raise ValueError("chunk_sectors must be positive")

    first = start_sector * storage_sector_size
    end_sector = start_sector + sector_count
    end = end_sector * storage_sector_size
    overlap = 16
    seen_offsets: set[int] = set()
    owned = not hasattr(source, "read")
    f = open(source, "rb") if owned else source  # type: ignore[arg-type]
    try:
        core_start = start_sector
        while core_start < end_sector:
            core_end = min(core_start + chunk_sectors, end_sector)
            read_start = max(start_sector, core_start - overlap)
            read_end = min(end_sector, core_end + overlap)
            read_offset = read_start * storage_sector_size
            read_size = (read_end - read_start) * storage_sector_size
            f.seek(read_offset)
            buffer = f.read(read_size)
            if len(buffer) != read_size:
                return

            for sector in range(core_start, core_end):
                absolute = sector * storage_sector_size
                rel = absolute - read_offset
                remaining = end - absolute
                if remaining < 0x400 or rel + 0x400 > len(buffer):
                    continue
                # EaseUS skips a sector when its first machine word is zero.
                if int.from_bytes(buffer[rel:rel + 8], "little") == 0:
                    continue
                size = _raw_file_record_size(buffer[rel:rel + 0x400])
                if size is None or size > remaining or rel + size > len(buffer):
                    continue
                raw = buffer[rel:rel + size]
                try:
                    record = parse_file_record(raw, number=-1, sector_size=storage_sector_size)
                except (ValueError, struct.error, UnicodeError):
                    continue
                if absolute in seen_offsets:
                    continue
                seen_offsets.add(absolute)
                special = next((name.name for name in record.names
                                if name.name in {"$MFT", "$MFTMirr", "$Bitmap"}), None)
                yield RawFileObservation(
                    offset=absolute,
                    sector=sector,
                    record_number=None,
                    sequence=record.sequence,
                    flags=record.flags,
                    record_size=size,
                    names=tuple(record.names),
                    special_name=special,
                    validation_status="validated",
                    record=record,
                )
            core_start = core_end
    finally:
        if owned:
            f.close()


@dataclasses.dataclass(frozen=True)
class MFTRegionObservation:
    """Compact metadata retained from a raw FILE observation."""
    offset: int
    sector: int
    record_number: Optional[int]
    sequence: int
    flags: int
    record_size: int
    names: tuple[str, ...]
    special_name: Optional[str]
    validation_status: str


@dataclasses.dataclass(frozen=True)
class MFTObservationConflict:
    """Two incompatible observations reported at one physical offset."""
    offset: int
    existing: MFTRegionObservation
    incoming: MFTRegionObservation


@dataclasses.dataclass(frozen=True)
class MFTRegionCandidate:
    """An inferred FILE-record region, not yet a validated MFT."""
    record_size: int
    start_offset: int
    end_offset: int
    observations: tuple[MFTRegionObservation, ...]
    layout: str
    contiguous_runs: int
    gaps: tuple[int, ...]
    system_name_clues: tuple[str, ...]
    evidence: tuple[str, ...]
    contradictions: tuple[str, ...]
    validation_state: str = "unvalidated"
    unresolved: tuple[str, ...] = (
        "MFT record-number origin",
        "volume start and boundary",
        "$MFT data runs",
        "$MFTMirr location and agreement",
        "$Bitmap allocation state",
    )


@dataclasses.dataclass(frozen=True)
class MFTRegionAnalysis:
    """Final compact result from :class:`MFTRegionAnalyzer`."""
    regions: tuple[MFTRegionCandidate, ...]
    isolated: tuple[MFTRegionObservation, ...]
    duplicates: int
    conflicts: tuple[MFTObservationConflict, ...]
    unvalidated: tuple[MFTRegionObservation, ...]
    record_size_hypotheses: tuple[int, ...]


class MFTRegionAnalyzer:
    """Incrementally group raw FILE observations into MFT-region hypotheses.

    The analyzer deliberately never converts a physical offset into an MFT
    record number. A candidate requires at least two compatible observations
    sharing a record-size boundary hypothesis; one FILE record remains
    isolated evidence only.
    """
    def __init__(self) -> None:
        self._by_offset: dict[int, MFTRegionObservation] = {}
        self._duplicates = 0
        self._conflicts: list[MFTObservationConflict] = []
        self._unvalidated: list[MFTRegionObservation] = []

    @staticmethod
    def _summary(observation: RawFileObservation) -> MFTRegionObservation:
        return MFTRegionObservation(
            offset=observation.offset,
            sector=observation.sector,
            record_number=observation.record_number,
            sequence=observation.sequence,
            flags=observation.flags,
            record_size=observation.record_size,
            names=tuple(name.name for name in observation.names),
            special_name=observation.special_name,
            validation_status=observation.validation_status,
        )

    @staticmethod
    def _identity(observation: MFTRegionObservation) -> tuple[object, ...]:
        return (observation.record_size, observation.sequence, observation.flags,
                observation.names, observation.special_name, observation.validation_status)

    def consume(self, observation: RawFileObservation) -> None:
        summary = self._summary(observation)
        if summary.validation_status != "validated":
            self._unvalidated.append(summary)
            return
        prior = self._by_offset.get(summary.offset)
        if prior is None:
            self._by_offset[summary.offset] = summary
        elif self._identity(prior) == self._identity(summary):
            self._duplicates += 1
        else:
            self._conflicts.append(MFTObservationConflict(summary.offset, prior, summary))

    def consume_all(self, observations: Iterable[RawFileObservation]) -> None:
        for observation in observations:
            self.consume(observation)

    def finish(self) -> MFTRegionAnalysis:
        by_size: dict[int, list[MFTRegionObservation]] = {}
        for observation in self._by_offset.values():
            by_size.setdefault(observation.record_size, []).append(observation)

        regions: list[MFTRegionCandidate] = []
        isolated: list[MFTRegionObservation] = []
        sizes = tuple(sorted(by_size))
        for record_size, observations in sorted(by_size.items()):
            by_boundary: dict[int, list[MFTRegionObservation]] = {}
            for observation in observations:
                by_boundary.setdefault(observation.offset % record_size, []).append(observation)
            for boundary_group in by_boundary.values():
                ordered = tuple(sorted(boundary_group, key=lambda item: item.offset))
                if len(ordered) < 2:
                    isolated.extend(ordered)
                    continue
                gaps = tuple(
                    right.offset - left.offset
                    for left, right in zip(ordered, ordered[1:])
                    if right.offset - left.offset != record_size
                )
                contiguous_runs = 1
                for left, right in zip(ordered, ordered[1:]):
                    if right.offset - left.offset != record_size:
                        contiguous_runs += 1
                layout = "contiguous" if not gaps else "fragmented"
                clues = tuple(sorted({name for item in ordered for name in item.names
                                      if name in {"$MFT", "$MFTMirr", "$Bitmap"}}))
                evidence = (
                    f"{len(ordered)} validated FILE observations",
                    f"record size hypothesis {record_size} bytes",
                    f"all offsets share boundary residue {ordered[0].offset % record_size}",
                    f"{contiguous_runs} contiguous run(s)",
                )
                if clues:
                    evidence += ("system-file name clues: " + ", ".join(clues),)
                contradictions = tuple(
                    f"other record-size hypothesis observed: {size} bytes"
                    for size in sizes if size != record_size
                )
                regions.append(MFTRegionCandidate(
                    record_size=record_size,
                    start_offset=ordered[0].offset,
                    end_offset=ordered[-1].offset + record_size,
                    observations=ordered,
                    layout=layout,
                    contiguous_runs=contiguous_runs,
                    gaps=gaps,
                    system_name_clues=clues,
                    evidence=evidence,
                    contradictions=contradictions,
                ))
        return MFTRegionAnalysis(
            regions=tuple(regions),
            isolated=tuple(sorted(isolated, key=lambda item: item.offset)),
            duplicates=self._duplicates,
            conflicts=tuple(self._conflicts),
            unvalidated=tuple(self._unvalidated),
            record_size_hypotheses=sizes,
        )


def analyze_mft_regions(observations: Iterable[RawFileObservation]) -> MFTRegionAnalysis:
    """Consume raw observations and return explainable MFT-region hypotheses."""
    analyzer = MFTRegionAnalyzer()
    analyzer.consume_all(observations)
    return analyzer.finish()


@dataclasses.dataclass(frozen=True)
class DirectoryIndexEvidence:
    """Compact directory/index evidence with optional independent volume identity."""
    source_offset: int
    index_kind: str
    volume_offset: Optional[int] = None
    record_number: Optional[int] = None
    sequence: Optional[int] = None
    record_size: Optional[int] = None
    validation_status: str = "validated"


@dataclasses.dataclass(frozen=True)
class CandidateEvidenceReport:
    """Explainable reconciliation result for one DBR-derived candidate."""
    candidate: NTFSCandidate
    rank: int
    ranking_basis: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    contradictory_evidence: tuple[str, ...]
    unresolved_fields: tuple[str, ...]
    provenance: tuple[str, ...]
    validation_status: str
    associated_raw_offsets: tuple[int, ...]
    associated_region_start: Optional[int]
    associated_directory_evidence: int


@dataclasses.dataclass(frozen=True)
class CandidateReconciliation:
    """Final result retaining associated and unassociated evidence separately."""
    candidates: tuple[CandidateEvidenceReport, ...]
    raw_observations: tuple[MFTRegionObservation, ...]
    mft_regions: tuple[MFTRegionCandidate, ...]
    directory_evidence: tuple[DirectoryIndexEvidence, ...]
    unassociated_raw_offsets: tuple[int, ...]
    unassociated_region_starts: tuple[int, ...]
    unassociated_directory_evidence: tuple[DirectoryIndexEvidence, ...]


class NTFSCandidateReconciler:
    """Incrementally reconcile DBR, FILE, MFT-region, and index evidence.

    Association is deliberately conservative: a raw FILE observation is
    associated only through an MFT-region candidate whose start equals the
    DBR-derived physical MFT location. Directory/index evidence requires an
    explicit matching ``volume_offset``. Physical proximity alone is never a
    relationship.
    """
    def __init__(self) -> None:
        self._candidates: list[NTFSCandidate] = []
        self._raw: dict[int, MFTRegionObservation] = {}
        self._regions: list[MFTRegionCandidate] = []
        self._directory: list[DirectoryIndexEvidence] = []

    @staticmethod
    def _raw_summary(observation: RawFileObservation) -> MFTRegionObservation:
        return MFTRegionAnalyzer._summary(observation)

    def add_candidate(self, candidate: NTFSCandidate) -> None:
        self._candidates.append(candidate)

    def add_raw_observation(self, observation: RawFileObservation) -> None:
        summary = self._raw_summary(observation)
        self._raw.setdefault(summary.offset, summary)

    def add_mft_region(self, region: MFTRegionCandidate) -> None:
        self._regions.append(region)

    def add_directory_evidence(self, evidence: DirectoryIndexEvidence) -> None:
        self._directory.append(evidence)

    def add_raw_observations(self, observations: Iterable[RawFileObservation]) -> None:
        for observation in observations:
            self.add_raw_observation(observation)

    def finalize(self) -> CandidateReconciliation:
        reports: list[CandidateEvidenceReport] = []
        associated_raw: set[int] = set()
        associated_regions: set[int] = set()
        associated_directory: set[int] = set()

        for candidate in self._candidates:
            geometry = candidate.geometry
            expected_mft = candidate.offset + geometry.mft_lcn * geometry.cluster_size
            matches = [region for region in self._regions
                       if region.start_offset == expected_mft]
            supporting = [f"{candidate.source_kind} DBR candidate at {candidate.offset:#x}"]
            contradictory: list[str] = []
            provenance = [candidate.source_kind]
            unresolved = [
                "partition boundary independently confirmed",
                "MFT record-number origin",
                "$MFTMirr record agreement",
                "$Bitmap allocation evidence",
            ]
            ranking_basis: list[str] = []
            raw_offsets: set[int] = set()
            region_start: Optional[int] = None
            if candidate.backup_matches:
                supporting.append("primary DBR has matching backup DBR")
                provenance.append("backup-DBR comparison")
                ranking_basis.append("backup DBR matches")
            if candidate.mft_record_readable:
                supporting.append("MFT record 0 readable")
                unresolved.remove("MFT record-number origin")
                ranking_basis.append("record 0 readable")
            if candidate.mft_runs_readable:
                supporting.append("MFT mapping pairs readable")
                unresolved.remove("partition boundary independently confirmed")
                ranking_basis.append("MFT mapping pairs readable")

            if matches:
                region = matches[0]
                region_start = region.start_offset
                associated_regions.add(id(region))
                supporting.extend(region.evidence)
                raw_offsets.update(item.offset for item in region.observations)
                associated_raw.update(raw_offsets)
                if region.record_size == geometry.record_size:
                    supporting.append("MFT-region record size matches DBR geometry")
                    ranking_basis.append("MFT region geometry matches")
                else:
                    contradictory.append(
                        f"MFT-region record size {region.record_size} differs from DBR geometry {geometry.record_size}"
                    )
                if region.system_name_clues:
                    supporting.append("system-file names are clues, not proof: " +
                                     ", ".join(region.system_name_clues))
            else:
                unresolved.append("MFT-region evidence at DBR-derived MFT location")

            directory_matches = [item for item in self._directory
                                 if item.validation_status == "validated" and
                                 item.volume_offset == candidate.offset]
            if directory_matches:
                associated_directory.update(id(item) for item in directory_matches)
                supporting.append(f"{len(directory_matches)} directory/index evidence item(s) explicitly identify this volume")
                ranking_basis.append("explicit directory volume identity")
            else:
                unresolved.append("directory/index evidence with explicit volume identity")

            if matches and any(region.contradictions for region in matches):
                contradictory.extend(matches[0].contradictions)
            if contradictory:
                validation_status = "contradictory-evidence"
            elif candidate.mft_record_readable and candidate.mft_runs_readable and matches:
                validation_status = "geometry-and-MFT-evidence"
            else:
                validation_status = "DBR-candidate-unresolved"
            reports.append(CandidateEvidenceReport(
                candidate=candidate,
                rank=0,
                ranking_basis=tuple(ranking_basis),
                supporting_evidence=tuple(supporting),
                contradictory_evidence=tuple(contradictory),
                unresolved_fields=tuple(dict.fromkeys(unresolved)),
                provenance=tuple(dict.fromkeys(provenance)),
                validation_status=validation_status,
                associated_raw_offsets=tuple(sorted(raw_offsets)),
                associated_region_start=region_start,
                associated_directory_evidence=len(directory_matches),
            ))

        reports.sort(key=lambda item: (
            item.validation_status != "contradictory-evidence",
            len(item.ranking_basis),
            len(item.supporting_evidence),
            item.candidate.offset,
        ), reverse=True)
        reports = [dataclasses.replace(item, rank=index + 1)
                   for index, item in enumerate(reports)]
        raw_offsets = set(self._raw)
        regions = tuple(self._regions)
        return CandidateReconciliation(
            candidates=tuple(reports),
            raw_observations=tuple(self._raw.values()),
            mft_regions=regions,
            directory_evidence=tuple(self._directory),
            unassociated_raw_offsets=tuple(sorted(raw_offsets - associated_raw)),
            unassociated_region_starts=tuple(sorted(
                region.start_offset for region in regions if id(region) not in associated_regions
            )),
            unassociated_directory_evidence=tuple(
                item for item in self._directory if id(item) not in associated_directory
            ),
        )


class NTFSVolume:
    """Random-access, read-only NTFS volume view."""
    def __init__(self, source: BinaryIO | str | Path, offset: int = 0):
        if offset < 0:
            raise ValueError("offset must be non-negative")
        self._owned = not hasattr(source, "read")
        self.f = open(source, "rb") if self._owned else source  # type: ignore[arg-type]
        self.offset = offset
        self.f.seek(offset)
        self.geometry = VolumeGeometry.from_boot_sector(self.f.read(512))
        try:
            self._source_stat = os.fstat(self.f.fileno()) if hasattr(self.f, "fileno") else None
        except (OSError, io.UnsupportedOperation):
            self._source_stat = None
        self._mft_runs: Optional[list[DataRun]] = None
        self._bitmap_cache: Optional[bytes] = None
        self._bitmap_error: Optional[str] = None

    def close(self) -> None:
        if self._owned: self.f.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def read_at(self, byte_offset: int, size: int) -> bytes:
        self.f.seek(self.offset + byte_offset)
        return self.f.read(size)
    def read_clusters(self, lcn: int, count: int) -> bytes:
        return self.read_at(lcn * self.geometry.cluster_size, count * self.geometry.cluster_size)
    def _record0(self) -> FileRecord:
        # Record 0 is the bootstrap needed to discover the fragmented $MFT.
        # Reading it through mft_runs() would recurse back into this method.
        raw = self.read_at(self.geometry.mft_lcn * self.geometry.cluster_size,
                           self.geometry.record_size)
        if len(raw) != self.geometry.record_size:
            raise ValueError("short MFT record")
        return parse_file_record(raw, 0, self.geometry.bytes_per_sector)
    def mft_runs(self) -> list[DataRun]:
        if self._mft_runs is None:
            data = next((a for a in self._record0().attrs if a.type == 0x80 and a.name == ""), None)
            if not data or data.resident: raise ValueError("$MFT has no nonresident unnamed data stream")
            self._mft_runs = data.runs
        return self._mft_runs
    def read_runs(self, runs: Iterable[DataRun], size: int, start_vcn: int = 0) -> bytes:
        """Read exactly ``size`` bytes covered by NTFS data runs.

        The older implementation silently returned a truncated buffer when a
        run gap or short source read occurred.  Recovery callers must receive
        either the complete stream or an exception, so this method validates
        run coverage and every physical read while retaining sparse and
        fragmented-run support.
        """
        if size < 0:
            raise ValueError("negative NTFS stream size")
        if size == 0:
            return b""
        cluster_size = self.geometry.cluster_size
        want_end = start_vcn + (size + cluster_size - 1) // cluster_size
        cursor_vcn = start_vcn
        out = bytearray()
        for run in sorted(runs, key=lambda item: item.vcn):
            if run.length <= 0 or (run.lcn is not None and run.lcn < 0):
                raise ValueError("malformed NTFS data run")
            if run.vcn + run.length <= cursor_vcn:
                continue
            if run.vcn >= want_end:
                break
            if run.vcn > cursor_vcn:
                raise ValueError("gap in NTFS data runs")
            first = max(cursor_vcn, run.vcn)
            run_offset = first - run.vcn
            available = min(run.length - run_offset, want_end - first)
            if available <= 0:
                continue
            if run.lcn is None:
                out.extend(b"\0" * (available * cluster_size))
            else:
                raw = self.read_clusters(run.lcn + run_offset, available)
                expected = available * cluster_size
                if len(raw) != expected:
                    raise IOError("short read while reading NTFS data run")
                out.extend(raw)
            cursor_vcn = first + available
            if cursor_vcn >= want_end:
                break
        if cursor_vcn < want_end:
            raise ValueError("NTFS data runs do not cover the requested stream")
        return bytes(out[:size])

    def iter_attribute_chunks(self, attr: Attribute, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        """Yield an attribute's bytes incrementally, including sparse runs."""
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if attr.resident:
            for pos in range(0, len(attr.value), chunk_size):
                yield attr.value[pos:pos + chunk_size]
            return

        remaining = attr.data_size
        initialized_remaining = min(max(attr.initialized_size, 0), remaining)
        cluster_size = self.geometry.cluster_size
        cursor_vcn = attr.lowest_vcn
        end_vcn = attr.lowest_vcn + (remaining + cluster_size - 1) // cluster_size
        for run in sorted(attr.runs, key=lambda item: item.vcn):
            if remaining <= 0 or run.vcn >= end_vcn:
                break
            if run.vcn + run.length <= cursor_vcn:
                continue
            if run.vcn > cursor_vcn:
                raise ValueError("gap in NTFS data runs")
            first = max(cursor_vcn, run.vcn)
            run_offset = first - run.vcn
            available = min(run.length - run_offset, end_vcn - first)
            physical = None if run.lcn is None else (run.lcn + run_offset) * cluster_size
            for cluster_offset in range(0, available * cluster_size, chunk_size):
                take = min(chunk_size, available * cluster_size - cluster_offset, remaining)
                if physical is None:
                    yield b"\0" * take
                else:
                    initialized_take = min(take, initialized_remaining)
                    if initialized_take:
                        data = self.read_at(physical + cluster_offset, initialized_take)
                        if len(data) != initialized_take:
                            raise IOError("short read while recovering data run")
                        yield data
                    if initialized_take < take:
                        yield b"\0" * (take - initialized_take)
                initialized_remaining = max(0, initialized_remaining - take)
                remaining -= take
            cursor_vcn = first + available
        if remaining:
            raise ValueError("NTFS data runs do not cover the data stream")
    def read_record(self, number: int, expand_attributes: bool = True) -> FileRecord:
        if number < 0:
            raise ValueError("negative MFT record number")
        runs = self.mft_runs()
        stream_size = sum(run.length for run in runs) * self.geometry.cluster_size
        off = self.geometry.record_size * number
        if off + self.geometry.record_size > stream_size:
            raise ValueError("MFT record number is outside the mapped $MFT stream")
        cluster_prefix = off % self.geometry.cluster_size
        raw = self.read_runs(
            runs,
            cluster_prefix + self.geometry.record_size,
            off // self.geometry.cluster_size,
        )[cluster_prefix:]
        if len(raw) != self.geometry.record_size: raise ValueError("short MFT record")
        record = parse_file_record(raw, number, self.geometry.bytes_per_sector)
        return self.expand_attributes(record) if expand_attributes else record

    def expand_attributes(self, record: FileRecord) -> FileRecord:
        """Merge attributes stored in extension FILE records via $ATTRIBUTE_LIST."""
        list_attr = next((attr for attr in record.attrs if attr.type == 0x20 and attr.name == ""), None)
        if list_attr is None:
            return record
        value = list_attr.value if list_attr.resident else self.read_runs(
            list_attr.runs, list_attr.data_size, list_attr.lowest_vcn)
        merged = list(record.attrs)
        seen = {(attr.type, attr.name, attr.instance, attr.lowest_vcn) for attr in merged}
        for entry in parse_attribute_list(value):
            if entry.file_reference == record.number:
                continue
            try:
                extension = self.read_record(entry.file_reference, expand_attributes=False)
            except (ValueError, struct.error):
                continue
            if entry.sequence and extension.sequence != entry.sequence:
                continue
            for attr in extension.attrs:
                if attr.type != entry.type or attr.name != entry.name or attr.instance != entry.instance:
                    continue
                key = (attr.type, attr.name, attr.instance, attr.lowest_vcn)
                if key not in seen:
                    seen.add(key)
                    merged.append(attr)
        names = [parse_file_name(attr.value) for attr in merged if attr.type == 0x30 and attr.resident]
        return dataclasses.replace(record, attrs=merged, names=names)
    def iter_mft(self, include_deleted: bool = True, limit: Optional[int] = None) -> Iterator[FileRecord]:
        total = sum(r.length for r in self.mft_runs()) * self.geometry.cluster_size // self.geometry.record_size
        for n in range(min(total, limit) if limit else total):
            try: rec = self.read_record(n)
            except (ValueError, struct.error): continue
            if include_deleted or rec.in_use: yield rec
    @staticmethod
    def _merged_attribute(rec: FileRecord, typ: int, name: str) -> Optional[Attribute]:
        matches = [attr for attr in rec.attrs if attr.type == typ and attr.name == name]
        if not matches:
            return None
        if len(matches) == 1 or any(attr.resident for attr in matches):
            return matches[0]
        first = matches[0]
        runs = sorted((run for attr in matches for run in attr.runs), key=lambda run: run.vcn)
        return dataclasses.replace(
            first,
            runs=runs,
            data_size=max(attr.data_size for attr in matches),
            initialized_size=max(attr.initialized_size for attr in matches),
            lowest_vcn=min(attr.lowest_vcn for attr in matches),
            highest_vcn=max(attr.highest_vcn for attr in matches),
        )

    def _recovery_data_attribute(self, rec: FileRecord, name: str = "") -> Optional[Attribute]:
        """Resolve one recovery DATA stream without hiding mixed forms."""
        matches = [attr for attr in rec.attrs if attr.type == 0x80 and attr.name == name]
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        if all(not attr.resident for attr in matches):
            return self._merged_attribute(rec, 0x80, name)
        raise ValueError("ambiguous unnamed $DATA attributes: resident and nonresident forms are mixed")

    def _validate_discovered_data(self, attr: Attribute) -> None:
        """Validate DATA mapping metadata without reading its physical clusters."""
        if attr.resident:
            return
        if attr.data_size < 0 or attr.initialized_size < 0 or attr.initialized_size > attr.data_size:
            raise ValueError("invalid DATA stream sizes")
        cluster_size = self.geometry.cluster_size
        cluster_count = (self.geometry.total_sectors + self.geometry.sectors_per_cluster - 1) // self.geometry.sectors_per_cluster
        stream_end = attr.lowest_vcn + (attr.data_size + cluster_size - 1) // cluster_size
        cursor = attr.lowest_vcn
        for run in sorted(attr.runs, key=lambda item: item.vcn):
            if run.length <= 0 or run.vcn < cursor:
                raise ValueError("overlapping or malformed DATA mapping pair")
            if run.vcn > cursor and cursor < stream_end:
                raise ValueError("gap in DATA mapping pairs")
            if run.lcn is not None and (run.lcn < 0 or run.lcn + run.length > cluster_count):
                raise ValueError("DATA mapping pair exceeds the NTFS volume")
            cursor = max(cursor, run.vcn + run.length)
            if cursor >= stream_end:
                break
        if cursor < stream_end:
            raise ValueError("DATA mapping pairs do not cover the stream")

    def discover_deleted_files(self, limit: Optional[int] = None) -> Iterator[DeletedFileDiscovery]:
        """Discover deleted FILE records without relying on directory indexes.

        The MFT traversal validates FILE signatures, USA fixups, record
        boundaries, and sequence fields.  This pass additionally requires a
        nonzero record sequence and one unambiguous unnamed DATA stream whose
        resident value or nonresident mapping pairs are structurally valid.
        Allocation is assessed but never overridden; extraction remains the
        responsibility of ``recover_selected``/``recover``.
        """
        for rec in self.iter_mft(include_deleted=True, limit=limit):
            if rec.in_use or rec.sequence == 0:
                continue
            try:
                data = self._recovery_data_attribute(rec, "")
                if data is None:
                    continue
                self._validate_discovered_data(data)
                allocation = self.assess_data_allocation(data)
            except (OSError, ValueError, struct.error):
                continue
            yield DeletedFileDiscovery(rec, data, allocation)

    def read_attribute(self, rec: FileRecord, typ: int = 0x80, name: str = "") -> bytes:
        a = self._merged_attribute(rec, typ, name)
        if not a: return b""
        return a.value if a.resident else self.read_runs(a.runs, a.data_size, a.lowest_vcn)
    def recover(self, rec: FileRecord, name: str = "", allow_deleted_uncertain: bool = False) -> bytes:
        attr = self._recovery_data_attribute(rec, name)
        if attr is None:
            return b""
        if not rec.in_use:
            allocation = self.assess_data_allocation(attr)
            if allocation.status not in {"unallocated", "not_applicable"} and not allow_deleted_uncertain:
                raise ValueError(
                    f"deleted-file allocation status {allocation.status} is not conservatively safe"
                )
        return attr.value if attr.resident else b"".join(self.iter_attribute_chunks(attr))

    @staticmethod
    def _preferred_names(records: dict[int, FileRecord]) -> dict[int, FileName]:
        result: dict[int, FileName] = {}
        for number, rec in records.items():
            if not rec.names:
                continue
            valid = [name for name in rec.names if name.parent not in records or
                     not name.parent_sequence or records[name.parent].sequence == name.parent_sequence]
            result[number] = sorted(valid or rec.names, key=lambda item: (item.namespace == 2, item.name))[0]
        return result

    @staticmethod
    def _path_for_record(number: int, names: dict[int, FileName]) -> str:
        parts: list[str] = []
        seen: set[int] = set()
        current = number
        while current in names and current not in seen and current != 5:
            seen.add(current)
            item = names[current]
            parts.append(item.name)
            current = item.parent
        return "\\" + "\\".join(reversed(parts)) if parts else "\\"

    @staticmethod
    def _safe_component(value: str, fallback: str) -> str:
        value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip().rstrip(".")
        return value if value and value not in {".", ".."} else fallback

    @staticmethod
    def _unique_file_path(path: Path, reserved: set[str]) -> Path:
        candidate = path
        stem, suffix = path.stem, path.suffix
        index = 1
        while candidate.exists() or str(candidate) in reserved:
            candidate = path.with_name(f"{stem} ({index}){suffix}")
            index += 1
        reserved.add(str(candidate))
        return candidate

    def recover_selected(
        self,
        destination: str | Path,
        records: Optional[Iterable[int]] = None,
        include_deleted: bool = True,
        limit: Optional[int] = None,
        log_path: Optional[str | Path] = None,
        chunk_size: int = 1024 * 1024,
        allow_deleted_uncertain: bool = False,
    ) -> list[dict[str, object]]:
        """Stream selected files using deterministic destination cleanup."""
        source_stat = getattr(self, "_source_stat", None)
        if source_stat is None:
            return self._recover_selected_impl(
                destination, records, include_deleted, limit, log_path,
                chunk_size, allow_deleted_uncertain, None)
        with _SecureDestination(destination, source_stat) as secure_destination:
            return self._recover_selected_impl(
                destination, records, include_deleted, limit, log_path,
                chunk_size, allow_deleted_uncertain, secure_destination)

    def _recover_selected_impl(
        self,
        destination: str | Path,
        records: Optional[Iterable[int]] = None,
        include_deleted: bool = True,
        limit: Optional[int] = None,
        log_path: Optional[str | Path] = None,
        chunk_size: int = 1024 * 1024,
        allow_deleted_uncertain: bool = False,
        secure_destination: Optional[_SecureDestination] = None,
    ) -> list[dict[str, object]]:
        """Stream selected files/directories to a separate destination.

        ``records`` contains MFT record numbers. A selected directory includes
        descendants whose FILE_NAME parent chains remain available. With no
        selection, every file with an unnamed DATA attribute is recovered.
        Deleted files whose nonresident DATA runs are currently allocated,
        mixed, or allocation-unknown are skipped unless
        ``allow_deleted_uncertain`` is explicitly true.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        destination = Path(destination)
        if secure_destination is None:
            if self._owned and destination.resolve() == Path(self.f.name).resolve():
                raise ValueError("recovery destination must differ from source")
            destination.mkdir(parents=True, exist_ok=True)
        log_file = Path(log_path) if log_path is not None else destination / "recovery-log.jsonl"
        if secure_destination is not None:
            log_file, log_handle = secure_destination.open_exclusive(log_file)
        else:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            log_handle = log_file.open("w", encoding="utf-8")

        records_by_number = {
            rec.number: rec for rec in self.iter_mft(include_deleted=include_deleted, limit=limit)
        }
        names = self._preferred_names(records_by_number)
        requested = None if records is None else {int(number) for number in records}
        selected = set(records_by_number) if requested is None else requested & set(records_by_number)
        if requested is not None:
            changed = True
            while changed:
                changed = False
                for number, name in names.items():
                    if name.parent in selected and number not in selected:
                        selected.add(number)
                        changed = True

        results: list[dict[str, object]] = []
        reserved: set[str] = set()
        with log_handle as log:
            def record_log(entry: dict[str, object]) -> None:
                results.append(entry)
                log.write(json.dumps(entry, ensure_ascii=False) + "\n")
                log.flush()

            ordered = sorted(selected, key=lambda number: (self._path_for_record(number, names).count("\\"), number))
            for number in ordered:
                rec = records_by_number[number]
                source_path = self._path_for_record(number, names)
                components = [self._safe_component(part, f"record-{number}") for part in source_path.strip("\\").split("\\") if part]
                if not components:
                    components = [f"record-{number}"]
                if rec.is_directory:
                    try:
                        target = (secure_destination.mkdir(components) if secure_destination is not None
                                  else destination.joinpath(*components))
                        if secure_destination is None:
                            target.mkdir(parents=True, exist_ok=True)
                        record_log({"status": "directory", "source_record": number, "size": 0,
                                    "source_path": source_path, "destination": str(target), "error": None})
                    except OSError as exc:
                        record_log({"status": "error", "source_record": number, "size": 0,
                                    "source_path": source_path, "destination": str(target), "error": str(exc)})
                    continue

                try:
                    data = self._recovery_data_attribute(rec, "")
                except ValueError as exc:
                    record_log({"status": "skipped", "source_record": number, "size": 0,
                                "source_path": source_path, "destination": None,
                                "error": str(exc), "allocation_status": "unknown",
                                "allocation_warnings": ["ambiguous DATA metadata is not conservatively safe"]})
                    continue
                if data is None:
                    record_log({"status": "skipped", "source_record": number, "size": 0,
                                "source_path": source_path, "destination": None,
                                "error": "no unnamed $DATA attribute",
                                "allocation_status": "unknown",
                                "allocation_warnings": ["allocation cannot be assessed without $DATA"]})
                    continue
                if rec.in_use:
                    allocation = AllocationAssessment(
                        "not-assessed", warnings=("active file; deleted-file allocation gate not applied",))
                else:
                    allocation = self.assess_data_allocation(data)
                    if allocation.status not in {"unallocated", "not_applicable"} and not allow_deleted_uncertain:
                        record_log({
                            "status": "skipped-allocation", "source_record": number,
                            "size": data.data_size if data.nonresident else len(data.value),
                            "source_path": source_path, "destination": None,
                            "allocation_status": allocation.status,
                            "allocation_warnings": list(allocation.warnings),
                            "override_used": False,
                            "error": "deleted-file allocation is not conservatively safe",
                        })
                        continue
                size = data.data_size if data.nonresident else len(data.value)
                target = destination.joinpath(*components)
                try:
                    if secure_destination is not None:
                        target, out = secure_destination.create_file(components, reserved)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target = self._unique_file_path(target, reserved)
                        out = target.open("xb")
                    with out:
                        for chunk in self.iter_attribute_chunks(data, chunk_size):
                            out.write(chunk)
                    record_log({"status": "recovered", "source_record": number, "size": size,
                                "source_path": source_path, "destination": str(target), "error": None,
                                "allocation_status": allocation.status,
                                "allocation_warnings": list(allocation.warnings),
                                "override_used": bool(not rec.in_use and allow_deleted_uncertain)})
                except (OSError, ValueError, struct.error) as exc:
                    try:
                        target.unlink(missing_ok=True)
                    except OSError:
                        pass
                    record_log({"status": "error", "source_record": number, "size": size,
                                "source_path": source_path, "destination": str(target), "error": str(exc),
                                "allocation_status": allocation.status,
                                "allocation_warnings": list(allocation.warnings),
                                "override_used": bool(not rec.in_use and allow_deleted_uncertain)})
        return results
    def directory_entries(self, rec: FileRecord, validate_references: bool = True) -> list[DirectoryEntry]:
        """Return de-duplicated, live entries from the directory's `$I30` index.

        INDEX_ALLOCATION is filtered through the directory's own `$BITMAP`
        when present.  File-reference sequence numbers are checked against the
        target FILE record to discard stale index entries left by reuse.
        """
        out: list[DirectoryEntry] = []
        index_bitmap = self.read_attribute(rec, 0xb0, "")
        for a in rec.attrs:
            if a.type == 0x90 and a.resident and len(a.value) >= 0x20:
                out.extend(parse_index_entries(a.value, 8))
            elif a.type == 0xa0 and not a.resident:
                raw = self.read_runs(a.runs, a.data_size, a.lowest_vcn)
                for off in range(0, len(raw), self.geometry.index_size):
                    block_number = off // self.geometry.index_size
                    if index_bitmap and (block_number // 8 >= len(index_bitmap) or
                                         not (index_bitmap[block_number // 8] & (1 << (block_number & 7)))):
                        continue
                    block = raw[off:off+self.geometry.index_size]
                    if block[:4] != b"INDX": continue
                    try:
                        fixed = apply_fixup(block, self.geometry.bytes_per_sector)
                        out.extend(parse_index_entries(fixed, 0x18))
                    except (ValueError, struct.error): pass
        unique: list[DirectoryEntry] = []
        seen: set[tuple[int, int, str, Optional[int]]] = set()
        for entry in out:
            if entry.end or entry.key is None:
                continue
            if validate_references:
                try:
                    target = self.read_record(entry.file_reference)
                except (ValueError, struct.error):
                    continue
                if entry.sequence and target.sequence != entry.sequence:
                    continue
            key = (entry.file_reference, entry.sequence, entry.key.name, entry.child_vcn)
            if key not in seen:
                seen.add(key)
                unique.append(entry)
        return unique

    def directory_index_counts(self, include_deleted: bool = True, limit: Optional[int] = None) -> dict[str, int]:
        """Return direct `$I30` child counts keyed by reconstructed directory path."""
        records = {rec.number: rec for rec in self.iter_mft(include_deleted=include_deleted, limit=limit)}
        names = self._preferred_names(records)
        counts: dict[str, int] = {}
        for number, rec in records.items():
            if not rec.is_directory:
                continue
            path = self._path_for_record(number, names)
            counts[path] = len(self.directory_entries(rec))
        return counts

    def directory_subtree_counts(self, include_deleted: bool = True, limit: Optional[int] = None) -> dict[str, int]:
        """Count all MFT items below each path, matching recovery UI semantics."""
        records = {rec.number: rec for rec in self.iter_mft(include_deleted=include_deleted, limit=limit)}
        names = self._preferred_names(records)
        counts: dict[str, int] = {}
        for number in records:
            path = self._path_for_record(number, names)
            parts = [part for part in path.strip("\\").split("\\") if part]
            for index in range(1, len(parts) + 1):
                parent = "\\" + "\\".join(parts[:index])
                if parent != path:
                    counts[parent] = counts.get(parent, 0) + 1
        return counts

    def compare_reference_counts(
        self,
        expected: Mapping[str, int],
        include_deleted: bool = True,
        limit: Optional[int] = None,
    ) -> dict[str, dict[str, Optional[int]]]:
        """Compare known EaseUS directory counts without changing recovery state."""
        observed = self.directory_subtree_counts(include_deleted=include_deleted, limit=limit)
        return {
            path: {"expected": count, "observed": observed.get(path),
                   "match": observed.get(path) == count}
            for path, count in expected.items()
        }

    def volume_bitmap(self) -> bytes:
        """Read $Bitmap's unnamed stream, useful for allocation-aware scans."""
        if self._bitmap_cache is not None:
            self._validate_bitmap_length(self._bitmap_cache)
            return self._bitmap_cache
        if self._bitmap_error is not None:
            raise ValueError(self._bitmap_error)
        try:
            bitmap = self.read_attribute(self.read_record(6), 0x80, "")
            self._validate_bitmap_length(bitmap)
        except (OSError, ValueError, struct.error) as exc:
            self._bitmap_error = f"unable to read $Bitmap: {exc}"
            raise ValueError(self._bitmap_error) from exc
        self._bitmap_cache = bitmap
        return bitmap

    def _validate_bitmap_length(self, bitmap: bytes) -> None:
        if not bitmap:
            raise ValueError("$Bitmap is empty or has no readable unnamed DATA")
        cluster_count = (self.geometry.total_sectors + self.geometry.sectors_per_cluster - 1) // self.geometry.sectors_per_cluster
        expected_bytes = (cluster_count + 7) // 8
        if len(bitmap) < expected_bytes:
            raise ValueError(
                f"$Bitmap is incomplete: {len(bitmap)} bytes, expected at least {expected_bytes}"
            )

    def cluster_allocated(self, cluster: int) -> Optional[bool]:
        """Return allocation evidence for one cluster.

        ``True`` and ``False`` represent observed bitmap bits.  ``None`` is
        returned when the bitmap is unavailable or does not cover the bit;
        unavailable evidence is never interpreted as free space.
        """
        if cluster < 0:
            return None
        try:
            bitmap = self.volume_bitmap()
        except (OSError, ValueError, struct.error):
            return None
        byte_index = cluster // 8
        cluster_count = (self.geometry.total_sectors + self.geometry.sectors_per_cluster - 1) // self.geometry.sectors_per_cluster
        if cluster >= cluster_count:
            return None
        if byte_index >= len(bitmap):
            return None
        return bool(bitmap[byte_index] & (1 << (cluster & 7)))

    def assess_data_allocation(self, attr: Attribute) -> AllocationAssessment:
        """Assess current ``$Bitmap`` state for every physical DATA cluster.

        This is evidence only.  Resident DATA is ``not_applicable`` because
        it has no source clusters.  Nonresident DATA deliberately returns
        ``unknown`` for a missing, unreadable, malformed, or incomplete
        bitmap and never treats an out-of-range bit as free.
        """
        if attr.resident:
            return AllocationAssessment(
                "not_applicable",
                warnings=(
                    "resident DATA is stored in the FILE record; no source clusters require allocation assessment",
                ),
            )
        if any(run.length <= 0 or (run.lcn is not None and run.lcn < 0) for run in attr.runs):
            return AllocationAssessment(
                "unknown",
                warnings=("malformed DATA run", "allocation evidence is incomplete"),
            )
        sparse_clusters = sum(run.length for run in attr.runs if run.lcn is None and run.length > 0)
        physical_runs = [run for run in attr.runs if run.lcn is not None]
        if not physical_runs:
            return AllocationAssessment(
                "unallocated", sparse_clusters=sparse_clusters,
                warnings=(
                    "all DATA runs are sparse; no source clusters were checked",
                    "unallocated does not prove original contents remain intact",
                ),
            )

        try:
            bitmap = self.volume_bitmap()
        except (OSError, ValueError, struct.error) as exc:
            return AllocationAssessment(
                "unknown", sparse_clusters=sparse_clusters,
                warnings=(str(exc), "missing bitmap evidence is not treated as free"),
            )

        total_clusters = (self.geometry.total_sectors + self.geometry.sectors_per_cluster - 1) // self.geometry.sectors_per_cluster
        expected_bitmap_bytes = (total_clusters + 7) // 8
        incomplete = len(bitmap) < expected_bitmap_bytes
        allocated = unallocated = checked = 0
        warnings: list[str] = []
        for run in physical_runs:
            assert run.lcn is not None
            for cluster in range(run.lcn, run.lcn + run.length):
                if cluster < 0 or cluster >= total_clusters or cluster // 8 >= len(bitmap):
                    incomplete = True
                    continue
                checked += 1
                if bitmap[cluster // 8] & (1 << (cluster & 7)):
                    allocated += 1
                else:
                    unallocated += 1
        if incomplete:
            warnings.append("$Bitmap is incomplete for one or more referenced clusters")
        if checked == 0 or incomplete:
            status = "unknown"
        elif allocated and unallocated:
            status = "mixed"
        elif allocated:
            status = "allocated"
        else:
            status = "unallocated"
        if status == "allocated":
            warnings.append("allocated clusters indicate potential reuse, not proof of overwrite")
        elif status == "mixed":
            warnings.append("mixed allocation indicates potential partial reuse, not proof of overwrite")
        elif status == "unallocated":
            warnings.append("unallocated does not prove original contents remain intact")
        return AllocationAssessment(
            status, allocated, unallocated, sparse_clusters, checked, tuple(warnings)
        )
    def scan_records(self, start: int = 0, end: Optional[int] = None, step: Optional[int] = None) -> Iterator[FileRecord]:
        step = step or self.geometry.record_size
        end = end if end is not None else self.geometry.total_sectors * self.geometry.bytes_per_sector
        for off in range(start, end, step):
            raw = self.read_at(off, self.geometry.record_size)
            if raw[:4] != b"FILE": continue
            try: yield parse_file_record(raw, off // self.geometry.record_size, self.geometry.bytes_per_sector)
            except (ValueError, struct.error): pass

    def inventory(self, include_deleted: bool = True, limit: Optional[int] = None) -> list[dict[str, object]]:
        """Build a path-oriented, allocation-aware recovery inventory.

        This consumes the same MFT, FILE_NAME, INDEX_ROOT and INDEX_ALLOCATION
        structures that the recovered pipeline feeds into its partition/file
        counters.  It does not write recovered data and does not require a
        mounted filesystem.
        """
        records: dict[int, FileRecord] = {}
        for rec in self.iter_mft(include_deleted=include_deleted, limit=limit):
            records[rec.number] = rec
        names: dict[int, FileName] = {}
        for number, rec in records.items():
            if rec.names:
                # Prefer Win32/POSIX namespace over DOS aliases.
                names[number] = sorted(rec.names, key=lambda n: (n.namespace == 2, n.name))[0]

        def path_for(number: int) -> str:
            parts: list[str] = []
            seen: set[int] = set()
            current = number
            while current in names and current not in seen and current != 5:
                seen.add(current)
                item = names[current]
                parts.append(item.name)
                current = item.parent
            return "\\" + "\\".join(reversed(parts)) if parts else "\\"

        rows: list[dict[str, object]] = []
        for number, rec in sorted(records.items()):
            name = names.get(number)
            data_attrs = [a for a in rec.attrs if a.type == 0x80 and a.name == ""]
            ambiguous_data_error: Optional[str] = None
            try:
                merged_data = self._recovery_data_attribute(rec, "")
            except ValueError as exc:
                merged_data = None
                ambiguous_data_error = str(exc)
            if rec.in_use:
                allocation = AllocationAssessment(
                    "not-assessed", warnings=("active file; deleted-file allocation gate not applied",))
            elif ambiguous_data_error is not None:
                allocation = AllocationAssessment(
                    "unknown", warnings=(ambiguous_data_error, "ambiguous DATA metadata is not conservatively safe"))
            elif merged_data is None:
                allocation = AllocationAssessment(
                    "unknown", warnings=("no unnamed $DATA attribute",))
            else:
                allocation = self.assess_data_allocation(merged_data)
            rows.append({
                "record": number,
                "path": path_for(number),
                "name": name.name if name else "",
                "parent": name.parent if name else None,
                "directory": rec.is_directory,
                "allocated": rec.in_use,
                "recoverable": bool(data_attrs),
                "metadata_recoverable": bool(data_attrs),
                "content_status": "not-assessed",
                "allocation_status": allocation.status,
                "allocation_warnings": list(allocation.warnings),
                "size": max((a.data_size if a.nonresident else len(a.value) for a in data_attrs), default=0),
                "names": len(rec.names),
            })
        return rows

    def write_inventory(self, output: str | Path, include_deleted: bool = True, limit: Optional[int] = None) -> int:
        """Write a tab-separated inventory to a different, caller-selected disk."""
        rows = self.inventory(include_deleted=include_deleted, limit=limit)
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as out:
            out.write("record\tpath\tdirectory\tallocated\trecoverable\tmetadata_recoverable\tcontent_status\tallocation_status\tallocation_warnings\tsize\n")
            for row in rows:
                out.write("{record}\t{path}\t{directory}\t{allocated}\t{recoverable}\t{metadata_recoverable}\t{content_status}\t{allocation_status}\t{allocation_warnings}\t{size}\n".format(
                    **{**row, "allocation_warnings": "; ".join(row["allocation_warnings"])}))
        return len(rows)


def _preview_metadata_confidence(row: Mapping[str, object]) -> str:
    if not row["metadata_recoverable"]:
        return "no-unnamed-data"
    if row["names"] and row["path"] != "\\":
        return "record-and-path"
    return "record-only"


def _preview_content_confidence(row: Mapping[str, object]) -> str:
    if row["directory"] or not row["metadata_recoverable"]:
        return "not-applicable"
    if row["allocated"]:
        return "active-file-not-assessed"
    status = row["allocation_status"]
    if status == "unallocated":
        return "potentially-original-unproven"
    if status in {"allocated", "mixed"}:
        return "potentially-reused"
    return "unknown"


def preview_recovery(
    source: BinaryIO | str | Path,
    candidate_offsets: Sequence[int],
    destination: str | Path,
    records: Optional[Iterable[int]] = None,
    include_deleted: bool = True,
    limit: Optional[int] = None,
) -> dict[str, object]:
    """Build a read-only recovery proposal from explicit NTFS offsets.

    Candidate discovery is intentionally caller-bounded: this function only
    validates the supplied offsets and reads their metadata/MFTs.  It never
    scans a device for candidates and never extracts file contents.
    """
    if destination is None:
        raise ValueError("preview destination is required")
    destination_path = Path(destination).expanduser().resolve()
    source_path = getattr(source, "name", None) if hasattr(source, "read") else source
    if source_path is None:
        raise ValueError("cannot verify a separate destination for an unnamed source")
    if destination_path == Path(source_path).expanduser().resolve():
        raise ValueError("preview destination must differ from source")
    offsets = list(dict.fromkeys(int(offset) for offset in candidate_offsets))
    if not offsets:
        raise ValueError("at least one explicit candidate offset is required")

    candidates: list[dict[str, object]] = []
    for offset in offsets:
        try:
            candidate = validate_ntfs_candidate(source, offset)
        except (ValueError, OSError, struct.error) as exc:
            candidates.append({"offset": offset, "accepted": False, "error": str(exc)})
            continue
        geometry = dataclasses.asdict(candidate.geometry)
        reasons = ["valid NTFS boot sector and supported geometry",
                   f"candidate extent is {candidate.length_bytes} bytes"]
        reasons.extend(candidate.notes)
        candidates.append({
            "offset": candidate.offset,
            "accepted": True,
            "source_kind": candidate.source_kind,
            "mode": candidate.mode,
            "length_bytes": candidate.length_bytes,
            "extent_sectors": candidate.extent_sectors,
            "geometry": geometry,
            "backup_offset": candidate.backup_offset,
            "backup_matches": candidate.backup_matches,
            "mft_offset": candidate.mft_offset,
            "mft_record_readable": candidate.mft_record_readable,
            "mft_runs_readable": candidate.mft_runs_readable,
            "reasons": reasons,
        })

    requested = None if records is None else {int(number) for number in records}
    volumes: list[dict[str, object]] = []
    for candidate in candidates:
        if not candidate["accepted"]:
            continue
        with NTFSVolume(source, offset=int(candidate["offset"])) as volume:
            rows = volume.inventory(include_deleted=include_deleted, limit=limit)
        by_number = {int(row["record"]): row for row in rows}
        selected = set(by_number) if requested is None else requested & set(by_number)
        if requested is not None:
            changed = True
            while changed:
                changed = False
                for row in rows:
                    parent = row["parent"]
                    number = int(row["record"])
                    if parent in selected and number not in selected:
                        selected.add(number)
                        changed = True
        files: list[dict[str, object]] = []
        for row in rows:
            item = dict(row)
            item["deleted"] = not bool(row["allocated"])
            item["metadata_confidence"] = _preview_metadata_confidence(row)
            item["content_confidence"] = _preview_content_confidence(row)
            item["selected"] = int(row["record"]) in selected
            files.append(item)
        volumes.append({
            "candidate": candidate,
            "selection": {
                "requested_records": sorted(requested) if requested is not None else None,
                "selected_records": sorted(selected),
                "selection_mode": "explicit-records-with-descendants" if requested is not None else "all-inventory-records",
            },
            "files": files,
        })
    return {
        "mode": "read-only-recovery-preview",
        "source": str(source_path),
        "destination": str(destination_path),
        "extraction_performed": False,
        "physical_scan_performed": False,
        "candidates": candidates,
        "volumes": volumes,
    }


def _source_identity_from_stat(path: Path, stat: os.stat_result) -> dict[str, object]:
    return {"path": str(path), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            "st_dev": stat.st_dev, "st_ino": stat.st_ino}


def _source_identity(source: BinaryIO | str | Path) -> dict[str, object]:
    source_path = getattr(source, "name", None) if hasattr(source, "read") else source
    if source_path is None:
        raise ValueError("manifest source must have a filesystem identity")
    path = Path(source_path).expanduser().resolve()
    return _source_identity_from_stat(path, path.stat())


def _manifest_digest(manifest: Mapping[str, object]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_recovery_manifest(path: str | Path, manifest: Mapping[str, object]) -> str:
    """Write a canonical, hash-protected recovery job manifest."""
    output = dict(manifest)
    output["manifest_sha256"] = _manifest_digest(output)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(output["manifest_sha256"])


def load_recovery_manifest(path: str | Path) -> dict[str, object]:
    """Load and verify a recovery manifest before it can drive extraction."""
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not manifest.get("manifest_sha256"):
        raise ValueError("recovery manifest has no integrity hash")
    expected = _manifest_digest(manifest)
    if manifest["manifest_sha256"] != expected:
        raise ValueError("recovery manifest hash mismatch")
    if manifest.get("manifest_version") != 1:
        raise ValueError("unsupported recovery manifest version")
    return manifest


def create_recovery_manifest(
    source: BinaryIO | str | Path,
    candidate_offsets: Sequence[int],
    destination: str | Path,
    records: Optional[Iterable[int]] = None,
    include_deleted: bool = True,
    limit: Optional[int] = None,
    output: Optional[str | Path] = None,
) -> dict[str, object]:
    """Create a reproducible preview manifest without extracting files."""
    report = preview_recovery(source, candidate_offsets, destination, records,
                              include_deleted=include_deleted, limit=limit)
    accepted = [item for item in report["candidates"] if item["accepted"]]
    if len(accepted) != 1:
        raise ValueError("manifest creation requires exactly one accepted candidate volume")
    volume = report["volumes"][0]
    manifest: dict[str, object] = {
        "manifest_version": 1,
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": _source_identity(source),
        "destination": report["destination"],
        "candidate": volume["candidate"],
        "selected_files": [item for item in volume["files"] if item["selected"]],
        "selection": volume["selection"],
        "warnings": [
            "Preview metadata is not proof that deleted bytes are original contents.",
            "Output SHA-256 values will verify extracted output only.",
        ],
        "extraction_performed": False,
        "physical_scan_performed": False,
    }
    manifest["manifest_sha256"] = _manifest_digest(manifest)
    if output is not None:
        write_recovery_manifest(output, manifest)
    return manifest


def recover_from_manifest(
    source: BinaryIO | str | Path,
    manifest_path: str | Path,
    allow_deleted_uncertain: bool = False,
    chunk_size: int = 1024 * 1024,
) -> dict[str, object]:
    """Revalidate and execute one previously previewed recovery manifest."""
    manifest = load_recovery_manifest(manifest_path)
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    source_path = Path(manifest["source"]["path"]).expanduser().resolve()
    candidate_info = manifest["candidate"]
    offset = int(candidate_info["offset"])
    selected_files = manifest["selected_files"]
    selected_records = [int(item["record"]) for item in selected_files]
    with source_path.open("rb") as pinned_source:
        pinned_stat = os.fstat(pinned_source.fileno())
        identity = _source_identity_from_stat(source_path, pinned_stat)
        if identity != manifest["source"]:
            raise ValueError("source identity differs from recovery manifest")
        destination = Path(manifest["destination"]).expanduser().resolve()
        if destination == source_path:
            raise ValueError("recovery destination must differ from source")
        candidate = validate_ntfs_candidate(pinned_source, offset)
        current_geometry = dataclasses.asdict(candidate.geometry)
        if current_geometry != candidate_info["geometry"] or candidate.length_bytes != candidate_info["length_bytes"]:
            raise ValueError("candidate geometry differs from recovery manifest")
        for field in ("backup_matches", "mft_record_readable", "mft_runs_readable"):
            if bool(getattr(candidate, field)) != bool(candidate_info.get(field, False)):
                raise ValueError(f"candidate validation differs for {field}")
        with NTFSVolume(pinned_source, offset=offset) as volume:
            current_rows = {int(row["record"]): row for row in volume.inventory(include_deleted=True)}
            for item in selected_files:
                number = int(item["record"])
                current = current_rows.get(number)
                if current is None:
                    raise ValueError(f"selected MFT record {number} is no longer readable")
                for field in ("path", "size", "allocated", "allocation_status"):
                    if current[field] != item[field]:
                        raise ValueError(f"selected record {number} metadata differs for {field}")
            if getattr(volume, "_source_stat", None) is not None:
                volume._source_stat = pinned_stat
            current_stat = os.fstat(pinned_source.fileno())
            if (current_stat.st_dev, current_stat.st_ino, current_stat.st_size,
                    current_stat.st_mtime_ns) != (pinned_stat.st_dev, pinned_stat.st_ino,
                                                   pinned_stat.st_size, pinned_stat.st_mtime_ns):
                raise ValueError("source changed before extraction")
            results = volume.recover_selected(
                destination, records=selected_records, include_deleted=True,
                chunk_size=chunk_size,
                allow_deleted_uncertain=allow_deleted_uncertain,
            )
            final_stat = os.fstat(pinned_source.fileno())
            if (final_stat.st_dev, final_stat.st_ino, final_stat.st_size,
                    final_stat.st_mtime_ns) != (pinned_stat.st_dev, pinned_stat.st_ino,
                                                pinned_stat.st_size, pinned_stat.st_mtime_ns):
                raise ValueError("source changed during extraction")
    final_files: list[dict[str, object]] = []
    for result in results:
        entry = dict(result)
        output_path = entry.get("destination")
        if entry.get("status") == "recovered" and output_path:
            output_file = Path(str(output_path))
            data = output_file.read_bytes()
            entry["bytes_written"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["content_authenticity"] = "output-integrity-only"
        else:
            entry["bytes_written"] = 0
            entry["sha256"] = None
            entry["content_authenticity"] = "not-established"
        final_files.append(entry)
    return {
        "report_version": 1,
        "manifest_sha256": manifest["manifest_sha256"],
        "started_utc": started_utc,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": identity,
        "destination": str(destination),
        "allow_deleted_uncertain": allow_deleted_uncertain,
        "warnings": [
            "SHA-256 verifies recovered output bytes only; it does not prove deleted bytes are original.",
        ],
        "files": final_files,
    }


def _main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="read-only NTFS MFT scanner/recoverer")
    p.add_argument("image"); p.add_argument("--deleted", action="store_true"); p.add_argument("--limit", type=int)
    p.add_argument("--offset-bytes", type=lambda value: int(value, 0), default=0,
                   metavar="BYTE_OFFSET", help="physical byte offset of the NTFS volume (decimal or 0x-prefixed hex)")
    p.add_argument("--candidate-offsets", metavar="BYTE_OFFSETS",
                   help="comma-separated explicit candidate offsets for --preview")
    p.add_argument("--preview", action="store_true",
                   help="validate explicit candidates and print a read-only recovery proposal")
    p.add_argument("--destination", type=Path,
                   help="required separate destination for --preview")
    p.add_argument("--preview-report", type=Path,
                   help="optional path for the JSON preview report")
    p.add_argument("--create-manifest", type=Path,
                   help="create a hash-protected recovery manifest without extracting files")
    p.add_argument("--recover-manifest", type=Path,
                   help="revalidate and execute a recovery manifest")
    p.add_argument("--recovery-report", type=Path,
                   help="optional JSON path for the final manifest recovery report")
    p.add_argument("--recover", type=int, metavar="MFT_RECORD"); p.add_argument("--output", type=Path)
    p.add_argument("--recover-root", type=Path, metavar="DESTINATION")
    p.add_argument("--records", metavar="MFT_RECORDS", help="comma-separated records; directories include descendants")
    p.add_argument("--recovery-log", type=Path)
    p.add_argument("--chunk-size", type=int, default=1024 * 1024)
    p.add_argument("--allow-deleted-uncertain", action="store_true",
                   help="override conservative allocation gating for deleted files")
    args = p.parse_args(argv)
    if args.create_manifest is not None and args.recover_manifest is not None:
        p.error("--create-manifest and --recover-manifest are mutually exclusive")
    if args.create_manifest is not None:
        if args.destination is None:
            p.error("--create-manifest requires --destination")
        offsets = ([int(value, 0) for value in args.candidate_offsets.split(",") if value.strip()]
                   if args.candidate_offsets else [args.offset_bytes])
        selected = None if not args.records else [int(value, 0) for value in args.records.split(",") if value.strip()]
        manifest = create_recovery_manifest(
            args.image, offsets, args.destination, records=selected,
            include_deleted=args.deleted, limit=args.limit, output=args.create_manifest,
        )
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return 0
    if args.recover_manifest is not None:
        report = recover_from_manifest(
            args.image, args.recover_manifest,
            allow_deleted_uncertain=args.allow_deleted_uncertain,
            chunk_size=args.chunk_size,
        )
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        print(rendered)
        if args.recovery_report is not None:
            if args.recovery_report.resolve() == Path(args.image).resolve():
                p.error("--recovery-report must differ from source")
            args.recovery_report.parent.mkdir(parents=True, exist_ok=True)
            args.recovery_report.write_text(rendered + "\n", encoding="utf-8")
        return 0
    if args.preview:
        if args.destination is None:
            p.error("--preview requires --destination")
        offsets = ([int(value, 0) for value in args.candidate_offsets.split(",") if value.strip()]
                   if args.candidate_offsets else [args.offset_bytes])
        selected = None if not args.records else [int(value, 0) for value in args.records.split(",") if value.strip()]
        report = preview_recovery(args.image, offsets, args.destination, records=selected,
                                  include_deleted=args.deleted, limit=args.limit)
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        print(rendered)
        if args.preview_report is not None:
            if args.preview_report.resolve() == Path(args.image).resolve():
                p.error("--preview-report must differ from source")
            args.preview_report.parent.mkdir(parents=True, exist_ok=True)
            args.preview_report.write_text(rendered + "\n", encoding="utf-8")
        return 0
    with NTFSVolume(args.image, offset=args.offset_bytes) as vol:
        print(dataclasses.asdict(vol.geometry))
        if args.recover_root is not None:
            selected = None if not args.records else [int(value, 0) for value in args.records.split(",") if value.strip()]
            results = vol.recover_selected(args.recover_root, records=selected,
                                           include_deleted=args.deleted, limit=args.limit,
                                           log_path=args.recovery_log, chunk_size=args.chunk_size,
                                           allow_deleted_uncertain=args.allow_deleted_uncertain)
            for result in results:
                print(json.dumps(result, ensure_ascii=False))
        elif args.recover is not None:
            data = vol.recover(vol.read_record(args.recover),
                               allow_deleted_uncertain=args.allow_deleted_uncertain)
            if args.output: args.output.write_bytes(data)
            else: print(f"recovered {len(data)} bytes")
        else:
            for rec in vol.iter_mft(include_deleted=args.deleted, limit=args.limit):
                for name in rec.names[:1]: print(rec.number, "active" if rec.in_use else "deleted", name.parent, name.name)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    try:
        return _main(argv)
    except (ValueError, OSError, struct.error, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__": raise SystemExit(main())
