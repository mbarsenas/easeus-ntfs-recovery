import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from src.ntfs_recovery import VHDXError, VHDXReader


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


def _guid(value: uuid.UUID) -> bytes:
    return value.bytes_le


def make_vhdx() -> bytes:
    block_size = 1024 * 1024
    virtual_size = block_size * 3
    host_size = 9 * 1024 * 1024
    image = bytearray(host_size)
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
        regions[pos:pos + 16] = _guid(identifier)
        struct.pack_into("<QII", regions, pos + 16, offset, length, flags)
    _checksum(regions, 4)
    image[0x30000:0x40000] = regions
    image[0x40000:0x50000] = regions

    metadata = bytearray(0x100000)
    metadata[:8] = b"metadata"
    struct.pack_into("<H", metadata, 0x0a, 4)
    values = [
        (VHDXReader.FILE_PARAMETERS_GUID, struct.pack("<II", block_size, 0)),
        (VHDXReader.VIRTUAL_SIZE_GUID, struct.pack("<Q", virtual_size)),
        (VHDXReader.LOGICAL_SECTOR_GUID, struct.pack("<I", 512)),
        (VHDXReader.PHYSICAL_SECTOR_GUID, struct.pack("<I", 512)),
    ]
    value_offset = 0x1000
    for index, (identifier, value) in enumerate(values):
        pos = 0x20 + index * 32
        metadata[pos:pos + 16] = _guid(identifier)
        struct.pack_into("<III", metadata, pos + 16, value_offset, len(value), 4)
        metadata[value_offset:value_offset + len(value)] = value
        value_offset += len(value)
    image[0x200000:0x300000] = metadata

    bat = {0: 6 | 0x500000, 2: 7 | 0x600000, 2048: 6 | 0x700000}
    for index, entry in bat.items():
        struct.pack_into("<Q", image, 0x300000 + index * 8, entry)
    image[0x500000:0x500000 + block_size] = b"A" * block_size
    image[0x600000:0x600000 + 512] = b"B" * 512
    image[0x600000 + 1024:0x600000 + 1536] = b"C" * 512
    image[0x700000] = 0b101
    return bytes(image)


class VHDXReaderTests(unittest.TestCase):
    def test_metadata_bat_bitmap_and_boundaries(self):
        with tempfile.NamedTemporaryFile() as source:
            source.write(make_vhdx())
            source.flush()
            with VHDXReader(source.name) as reader:
                self.assertEqual(reader.virtual_size, 3 * 1024 * 1024)
                self.assertEqual(reader.logical_sector_size, 512)
                self.assertEqual(reader.read_at(0, 512), b"A" * 512)
                self.assertEqual(reader.read_at(1024 * 1024, 512), b"\0" * 512)
                self.assertEqual(reader.read_at(2 * 1024 * 1024, 512), b"B" * 512)
                self.assertEqual(reader.read_at(2 * 1024 * 1024 + 512, 512), b"\0" * 512)
                self.assertEqual(reader.read_at(2 * 1024 * 1024 + 1024, 512), b"C" * 512)
                self.assertEqual(len(reader.read_at(reader.virtual_size - 10, 100)), 10)
                with self.assertRaises(ValueError):
                    reader.read_at(reader.virtual_size + 1, 1)

    def test_invalid_metadata_checksum_is_rejected(self):
        image = bytearray(make_vhdx())
        image[0x30000 + 40] ^= 1
        image[0x40000 + 40] ^= 1
        with tempfile.NamedTemporaryFile() as source:
            source.write(image)
            source.flush()
            with self.assertRaises(VHDXError):
                VHDXReader(source.name)

    def test_invalid_signature_is_rejected(self):
        image = bytearray(make_vhdx())
        image[:8] = b"notvhdx!"
        with tempfile.NamedTemporaryFile() as source:
            source.write(image)
            source.flush()
            with self.assertRaises(VHDXError):
                VHDXReader(source.name)


if __name__ == "__main__":
    unittest.main()
