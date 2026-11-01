#!/usr/bin/env python3
"""Run the disposable NTFS image benchmark and write one JSON result report."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

# Make direct ``python3 fixtures/run_ntfs_benchmark.py`` invocation behave the
# same as importing the runner from the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fixtures.generate_ntfs_test_image import generate_image
from src.ntfs_recovery import NTFSVolume, validate_ntfs_candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _separate_destination(source: Path, requested: Optional[Path]) -> tuple[Path, bool]:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=True)
        if source.stat().st_dev == requested.stat().st_dev:
            raise RuntimeError("benchmark destination must be on a different filesystem")
        return requested, False
    shm = Path("/dev/shm")
    if not shm.is_dir():
        raise RuntimeError("no default separate destination filesystem; pass --destination")
    destination = Path(tempfile.mkdtemp(prefix="ntfs-benchmark-", dir=shm))
    return destination, True


def run_benchmark(
    report_path: str | Path,
    *,
    image_path: Optional[str | Path] = None,
    manifest_path: Optional[str | Path] = None,
    destination: Optional[str | Path] = None,
) -> dict[str, object]:
    report_path = Path(report_path)
    temporary_root: Optional[Path] = None
    temporary_destination = False
    errors: list[str] = []
    warnings: list[str] = []
    files_report: list[dict[str, object]] = []
    result: dict[str, object] = {
        "format": "easeus-ntfs-recovery.synthetic-benchmark.v1",
        "image": {},
        "candidate": {},
        "inventory": {},
        "files": files_report,
        "allocation_safety": {},
        "errors": errors,
        "warnings": warnings,
        "pass": False,
    }
    try:
        if image_path is None or manifest_path is None:
            temporary_root = Path(tempfile.mkdtemp(prefix="ntfs-benchmark-"))
            image = temporary_root / "fixture.img"
            manifest = temporary_root / "fixture.json"
        else:
            image = Path(image_path)
            manifest = Path(manifest_path)

        expected_manifest = generate_image(image, manifest)
        result["image"] = {
            "path": str(image),
            "size": image.stat().st_size,
            "sha256": _sha256(image),
            "manifest": str(manifest),
        }
        expected = {int(item["record"]): item for item in expected_manifest["files"]}

        candidate = validate_ntfs_candidate(image, 0)
        result["candidate"] = {
            "count": 1,
            "offset_bytes": candidate.offset,
            "volume_bytes": candidate.volume_bytes,
            "mft_record_readable": candidate.mft_record_readable,
            "mft_runs_readable": candidate.mft_runs_readable,
            "backup_matches": candidate.backup_matches,
            "notes": list(candidate.notes),
        }

        destination_path, temporary_destination = _separate_destination(
            image, Path(destination) if destination is not None else None
        )
        with NTFSVolume(image) as volume:
            inventory = volume.inventory(include_deleted=True)
            inventory_by_record = {int(row["record"]): row for row in inventory}
            result["inventory"] = {
                "count": len(inventory),
                "malformed_record_14_present": 14 in inventory_by_record,
            }
            selected = sorted(expected)
            recovery = volume.recover_selected(
                destination_path, records=selected, include_deleted=True
            )
            actual_by_record = {int(row["source_record"]): row for row in recovery}

            allocation_statuses: dict[str, str] = {}
            for record, expectation in expected.items():
                actual = actual_by_record.get(record)
                expected_status = str(expectation["status"])
                actual_status = str(actual["status"]) if actual else "missing"
                status_match = actual_status == expected_status
                output_hash = None
                expected_hash = expectation.get("sha256")
                hash_match = None
                output_path = actual.get("destination") if actual else None
                if output_path and Path(output_path).is_file():
                    output_hash = _sha256(Path(output_path))
                    hash_match = output_hash == expected_hash
                allocation = str(
                    (actual or {}).get(
                        "allocation_status", inventory_by_record.get(record, {}).get("allocation_status", "unknown")
                    )
                )
                allocation_statuses[str(record)] = allocation
                if not status_match:
                    errors.append(
                        f"record {record}: expected status {expected_status}, got {actual_status}"
                    )
                if expected_status == "recovered" and expected_hash is not None and hash_match is not True:
                    errors.append(
                        f"record {record}: SHA-256 mismatch (expected {expected_hash}, got {output_hash})"
                    )
                files_report.append({
                    "record": record,
                    "path": expectation["path"],
                    "expected_status": expected_status,
                    "actual_status": actual_status,
                    "status_match": status_match,
                    "expected_size": expectation["size"],
                    "actual_size": actual.get("size") if actual else None,
                    "expected_sha256": expected_hash,
                    "actual_sha256": output_hash,
                    "sha256_match": hash_match,
                    "allocation_status": allocation,
                    "allocation_warnings": list((actual or {}).get("allocation_warnings", [])),
                    "error": (actual or {}).get("error"),
                })
            result["allocation_safety"] = {
                "by_record": allocation_statuses,
                "mixed_deleted_skipped": actual_by_record.get(13, {}).get("status") == "skipped-allocation",
                "unallocated_deleted_recovered": actual_by_record.get(12, {}).get("status") == "recovered",
            }
            if 14 in inventory_by_record:
                errors.append("malformed record 14 was unexpectedly inventoried")
            if not result["candidate"]["mft_record_readable"]:
                errors.append("candidate MFT record 0 was not readable")
            if not result["candidate"]["mft_runs_readable"]:
                errors.append("candidate MFT runs were not readable")
    except Exception as exc:  # benchmark report should retain the failure context
        errors.append(f"benchmark exception: {type(exc).__name__}: {exc}")
    finally:
        if temporary_destination:
            shutil.rmtree(destination_path, ignore_errors=True)
        if temporary_root is not None:
            shutil.rmtree(temporary_root, ignore_errors=True)

    result["pass"] = not errors
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--image", type=Path, help="preserve generated image at this path")
    parser.add_argument("--manifest", type=Path, help="preserve generated manifest at this path")
    parser.add_argument("--destination", type=Path,
                        help="existing destination on a different filesystem")
    args = parser.parse_args(argv)
    if (args.image is None) != (args.manifest is None):
        parser.error("--image and --manifest must be supplied together")
    result = run_benchmark(
        args.report, image_path=args.image, manifest_path=args.manifest,
        destination=args.destination,
    )
    print(json.dumps({"report": str(args.report), "pass": result["pass"]}, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
