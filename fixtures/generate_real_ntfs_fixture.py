#!/usr/bin/env python3
"""Create and validate a disposable, formatter-created NTFS image.

The successful path requires ``mkntfs`` and a user-space NTFS mounter
(``ntfs-3g``).  It never accepts a device path and never invokes privileged
mounting.  If the population backend is unavailable, it writes a manifest and
an explicit blocked report without claiming that a fixture was validated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


RESIDENT = b"real-ntfs-resident-fixture\n"
DELETED = (b"real-ntfs-deleted-fixture\n" * 256)
LARGE_SIZE = 2 * 1024 * 1024


def _large_bytes() -> bytes:
    return bytes((index * 37 + 11) & 0xff for index in range(LARGE_SIZE))


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tools() -> dict[str, Optional[str]]:
    return {name: shutil.which(name) for name in ("mkntfs", "ntfs-3g", "fusermount3", "fusermount")}


def _manifest_template() -> dict[str, object]:
    large = _large_bytes()
    return {
        "format": "easeus-ntfs-recovery.real-ntfs-fixture.v1",
        "status": "planned",
        "files": [
            {"path": "/Root/Resident.txt", "size": len(RESIDENT), "sha256": _hash(RESIDENT), "deleted": False},
            {"path": "/Root/Nested/Large.bin", "size": len(large), "sha256": _hash(large), "deleted": False},
            {"path": "/Root/Nested/DeleteMe.bin", "size": len(DELETED), "sha256": _hash(DELETED), "deleted": True},
        ],
        "notes": [
            "Hashes are of host bytes before copying into the image.",
            "Deleted-file recovery is successful only if recovered output hashes match.",
        ],
    }


def _write_manifest(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def generate_fixture(image: Path, manifest_path: Path, report_path: Path) -> dict[str, object]:
    if image.is_absolute() and str(image).startswith("/dev/"):
        raise ValueError("refusing to use a device path as the image")
    tools = _tools()
    manifest = _manifest_template()
    report: dict[str, object] = {
        "format": "easeus-ntfs-recovery.real-ntfs-validation.v1",
        "status": "blocked",
        "tools": tools,
        "image": str(image),
        "manifest": str(manifest_path),
        "recognized_structures": {},
        "errors": [],
        "warnings": [],
    }
    _write_manifest(manifest_path, manifest)

    missing = []
    if not tools["mkntfs"]:
        missing.append("mkntfs")
    if not tools["ntfs-3g"]:
        missing.append("ntfs-3g (required for nested directories and deletion without privileged mounting)")
    elif not Path("/dev/fuse").exists():
        missing.append("usable FUSE device (/dev/fuse is absent or inaccessible)")
    if missing:
        report["errors"] = ["required utility unavailable: " + item for item in missing]
        report["next_step"] = "Provide a usable non-root ntfs-3g/FUSE backend, then rerun; no image was created."
        _write_manifest(manifest_path, manifest)
        _write_manifest(report_path, report)
        return report

    work = Path(tempfile.mkdtemp(prefix="real-ntfs-fixture-"))
    mountpoint = work / "mnt"
    host = work / "host"
    mounted = False
    try:
        image.parent.mkdir(parents=True, exist_ok=True)
        with image.open("wb") as stream:
            stream.truncate(128 * 1024 * 1024)
        formatted = _run([tools["mkntfs"], "-F", "-Q", "-L", "REALFIXTURE", str(image)])
        if formatted.returncode != 0:
            raise RuntimeError(formatted.stderr.strip() or "mkntfs failed")
        mountpoint.mkdir()
        host.mkdir()
        (host / "Resident.txt").write_bytes(RESIDENT)
        (host / "Large.bin").write_bytes(_large_bytes())
        (host / "DeleteMe.bin").write_bytes(DELETED)
        mount = _run([tools["ntfs-3g"], "-o", f"loop,uid={os.getuid()},gid={os.getgid()}", str(image), str(mountpoint)], check=False)
        if mount.returncode != 0:
            raise RuntimeError("ntfs-3g mount failed: " + (mount.stderr.strip() or mount.stdout.strip()))
        mounted = True
        (mountpoint / "Root" / "Nested").mkdir(parents=True)
        shutil.copyfile(host / "Resident.txt", mountpoint / "Root" / "Resident.txt")
        shutil.copyfile(host / "Large.bin", mountpoint / "Root" / "Nested" / "Large.bin")
        shutil.copyfile(host / "DeleteMe.bin", mountpoint / "Root" / "Nested" / "DeleteMe.bin")
        # This is the only deletion: it occurs inside the disposable image.
        (mountpoint / "Root" / "Nested" / "DeleteMe.bin").unlink()
        unmount = tools["fusermount3"] or tools["fusermount"] or "umount"
        command = [unmount, "-u", str(mountpoint)] if "fuser" in Path(unmount).name else [unmount, str(mountpoint)]
        result = _run(command, check=False)
        if result.returncode != 0:
            raise RuntimeError("unmount failed: " + (result.stderr.strip() or result.stdout.strip()))
        mounted = False

        # Import only after the fixture has been created; this is the same
        # parser used by the normal recovery CLI.
        from src.ntfs_recovery import NTFSVolume, preview_recovery, validate_ntfs_candidate
        candidate = validate_ntfs_candidate(image, 0)
        with NTFSVolume(image) as volume:
            rows = volume.inventory(include_deleted=True)
        preview_destination = work / "preview-destination"
        preview_destination.mkdir()
        preview = preview_recovery(image, [0], preview_destination)
        report["status"] = "passed"
        report["image_size"] = image.stat().st_size
        report["image_sha256"] = _hash(image.read_bytes())
        report["candidate"] = {
            "count": 1, "mft_record_readable": candidate.mft_record_readable,
            "mft_runs_readable": candidate.mft_runs_readable,
            "backup_matches": candidate.backup_matches,
        }
        report["inventory_count"] = len(rows)
        report["preview"] = preview
        report["recognized_structures"] = {
            "boot_sector_geometry": True,
            "mft_record_zero": candidate.mft_record_readable,
            "mft_data_runs": candidate.mft_runs_readable,
            "file_name_paths": any(row.get("path") == r"\Root\Nested\Large.bin" for row in rows),
            "deleted_record_visibility": any(not row["allocated"] for row in rows),
            "directory_indexes": "not independently reported by current inventory API",
        }
        manifest["status"] = "created-and-populated"
        manifest["image_sha256"] = report["image_sha256"]
        _write_manifest(manifest_path, manifest)
    except Exception as exc:
        report["errors"] = [f"{type(exc).__name__}: {exc}"]
    finally:
        if mounted:
            unmount = tools["fusermount3"] or tools["fusermount"] or "umount"
            command = [unmount, "-u", str(mountpoint)] if "fuser" in Path(unmount).name else [unmount, str(mountpoint)]
            _run(command, check=False)
        shutil.rmtree(work, ignore_errors=True)
    _write_manifest(manifest_path, manifest)
    _write_manifest(report_path, report)
    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = generate_fixture(args.image, args.manifest, args.report)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}")
        return 2
    print(json.dumps({"status": result["status"], "report": str(args.report)}, sort_keys=True))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
