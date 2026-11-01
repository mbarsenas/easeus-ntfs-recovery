# `/dev/sdg` read-only recovery status

Date: 2026-11-01

## Existing scan state

The prior scanner is `/home/mbarsenas/ntfs_scan.py`. It scans a hard-coded
4,000,787,029,504-byte `/dev/sdg` range for sector-aligned `NTFS    ` OEM
strings, but no running `ntfs_scan.py` process, output log, candidate list, or
report was present. The recovery project itself contains no prior device scan
artifacts.

## Device observations

Read-only device inventory reported:

- `/dev/sdg`: 3.6 TB, read-only, model `BUP BK`, serial `NA7TGH0W`
- `/dev/sdg1`: sectors 64–263, 100 KiB, read-only
- `/dev/sdg2`: sectors 264–6023, 2.8 MiB, read-only, vfat
- `/dev/sdg3`: sectors 6024–55335, 24.1 MiB, read-only, hfsplus
- `/dev/sdg4`: sectors 55336–55935, 300 KiB, read-only
- Existing mount: `/dev/sdg` at `/mnt/seagate-check`, ISO9660, read-only, 28 MiB

The accessible mount contains boot/EFI files only. It is not the expected NTFS
data volume.

## Resumed read-only verification

The ACL is now effective: a direct 512-byte read succeeded, and the kernel
reports `/dev/sdg` as read-only. The first sector is a protective MBR (`0xee`);
the GPT describes only four small partitions ending at LBA 55,935. No large
GPT data partition is declared.

Known partition starts and the region immediately after them were probed. None
contained an NTFS OEM string. A bounded signature scan from 28 MiB through 2
GiB also found no sector-aligned `NTFS    ` boot signature.

## Current blocking condition

Access is now available, but no credible NTFS candidate has been found. A
remaining-device scan was started at 2 GiB and stopped after approximately
1.9 GiB because the device sustained only about 40 MiB/s, implying many hours
for the remaining 4 TB. It produced no candidate before stopping. No boot
geometry, MFT location, or file-record readability can yet be validated.

No mount, filesystem repair, partition write, CHKDSK, or other mutating action
was attempted.

## Resume action

The next efficient input is a prior scan result, a known byte offset for the
NTFS volume, or a read-only image/clone with a partition map. Once an offset is
known, `src/ntfs_recovery.py` can consume it directly, validate the primary and
backup boot sectors, validate `$MFT` record 0 and its unnamed `$DATA` runs,
then enumerate active/deleted records and recover to a different drive.
