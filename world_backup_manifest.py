#!/usr/bin/env python3
"""Create and verify deterministic SHA-256 backup manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


class ManifestError(ValueError):
    """Raised when a backup tree or manifest is unsafe or invalid."""


def _display(path: object) -> str:
    """Quote untrusted paths so control characters cannot affect terminals."""
    return json.dumps(str(path), ensure_ascii=True)


def _same_object(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _hash_regular_file(
    directory_fd: int, name: str, relative: str, expected: os.stat_result
) -> dict[str, object]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ManifestError(f"cannot open {_display(relative)} safely: {exc.strerror}") from exc
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or not _same_object(expected, before):
            raise ManifestError(f"backup changed during scan: {_display(relative)}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise ManifestError(f"file changed while hashing: {_display(relative)}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise ManifestError(f"file changed while hashing: {_display(relative)}")
        after = os.fstat(file_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise ManifestError(f"file changed while hashing: {_display(relative)}")
        return {"path": relative, "size": before.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(file_fd)


def _scan_directory(directory_fd: int, prefix: str, files: list[dict[str, object]]) -> None:
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        location = prefix or "."
        raise ManifestError(f"cannot list {_display(location)}: {exc.strerror}") from exc

    for name in names:
        relative = f"{prefix}/{name}" if prefix else name
        if "\\" in name:
            raise ManifestError(f"unsupported filename: {_display(relative)}")
        try:
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise ManifestError(f"cannot inspect {_display(relative)}: {exc.strerror}") from exc

        if stat.S_ISLNK(entry.st_mode):
            raise ManifestError(f"symbolic link is not allowed: {_display(relative)}")
        if stat.S_ISREG(entry.st_mode):
            files.append(_hash_regular_file(directory_fd, name, relative, entry))
            continue
        if stat.S_ISDIR(entry.st_mode):
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise ManifestError(
                    f"cannot open directory {_display(relative)} safely: {exc.strerror}"
                ) from exc
            try:
                opened = os.fstat(child_fd)
                if not _same_object(entry, opened):
                    raise ManifestError(f"backup changed during scan: {_display(relative)}")
                _scan_directory(child_fd, relative, files)
            finally:
                os.close(child_fd)
            continue
        raise ManifestError(f"entry is not a regular file or directory: {_display(relative)}")


def _open_directory_path(path: Path) -> int:
    """Open every path component without following symbolic links."""
    if not all(
        hasattr(os, name) for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    ):
        raise ManifestError("this platform lacks safe no-follow filesystem operations")
    parts = path.parts
    if ".." in parts:
        raise ManifestError(f"backup path cannot contain '..': {_display(path)}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open("/" if path.is_absolute() else ".", flags)
    components = parts[1:] if path.is_absolute() else parts
    try:
        for component in components:
            if component in ("", "."):
                continue
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError:
        os.close(current_fd)
        raise


def build_manifest(root: Path) -> dict[str, object]:
    """Return a deterministic manifest for regular files below *root*."""
    root = Path(root)
    try:
        root_fd = _open_directory_path(root)
    except OSError as exc:
        raise ManifestError(f"backup root is not a safe directory: {_display(root)}") from exc
    try:
        files: list[dict[str, object]] = []
        _scan_directory(root_fd, "", files)
    finally:
        os.close(root_fd)
    return {"format_version": 1, "algorithm": "sha256", "files": files}


def _validated_entries(manifest: object) -> list[dict[str, object]]:
    if not isinstance(manifest, dict):
        raise ManifestError("manifest must be a JSON object")
    if set(manifest) != {"format_version", "algorithm", "files"}:
        raise ManifestError("manifest contains unknown or missing top-level fields")
    if type(manifest.get("format_version")) is not int or manifest["format_version"] != 1:
        raise ManifestError("unsupported manifest format or algorithm")
    if manifest.get("algorithm") != "sha256":
        raise ManifestError("unsupported manifest format or algorithm")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ManifestError("manifest files must be an array")

    validated = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ManifestError("each manifest file must be an object")
        if set(entry) != {"path", "size", "sha256"}:
            raise ManifestError("manifest file contains unknown or missing fields")
        path = entry.get("path")
        size = entry.get("size")
        checksum = entry.get("sha256")
        if not isinstance(path, str) or not path or "\\" in path:
            raise ManifestError("manifest contains an invalid path")
        pure_path = PurePosixPath(path)
        if (
            path == "."
            or pure_path.is_absolute()
            or ".." in pure_path.parts
            or pure_path.as_posix() != path
        ):
            raise ManifestError(f"manifest contains an unsafe path: {_display(path)}")
        if path in seen:
            raise ManifestError(f"manifest contains a duplicate path: {_display(path)}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestError(f"manifest contains an invalid size for: {_display(path)}")
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise ManifestError(f"manifest contains an invalid sha256 for: {_display(path)}")
        seen.add(path)
        validated.append(entry)
    return validated


def verify_manifest(root: Path, manifest: object) -> dict[str, object]:
    """Compare *root* with a previously created manifest."""
    expected_entries = _validated_entries(manifest)
    current = build_manifest(root)
    expected_by_path = {entry["path"]: entry for entry in expected_entries}
    current_by_path = {entry["path"]: entry for entry in current["files"]}

    expected_paths = set(expected_by_path)
    current_paths = set(current_by_path)
    missing = sorted(expected_paths - current_paths)
    unexpected = sorted(current_paths - expected_paths)
    modified = sorted(
        path
        for path in expected_paths & current_paths
        if expected_by_path[path] != current_by_path[path]
    )
    matched = len(expected_paths & current_paths) - len(modified)
    return {
        "ok": not (missing or modified or unexpected),
        "matched": matched,
        "missing": missing,
        "modified": modified,
        "unexpected": unexpected,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and verify SHA-256 manifests for game-world backups."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="write a manifest to standard output")
    create.add_argument("world", type=Path)

    verify = subparsers.add_parser("verify", help="verify a world against a manifest")
    verify.add_argument("world", type=Path)
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _human_report(result: dict[str, object]) -> str:
    if result["ok"]:
        return f"OK: {result['matched']} file(s) matched"
    lines = [f"DRIFT: {result['matched']} file(s) matched"]
    for label in ("missing", "modified", "unexpected"):
        for path in result[label]:
            lines.append(f"{label.upper()}: {_display(path)}")
    return "\n".join(lines)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {_display(key)}")
        result[key] = value
    return result


def _read_manifest(path: Path) -> object:
    """Read one stable regular manifest without following links or waiting on FIFOs."""
    parent_fd = _open_directory_path(path.parent)
    try:
        expected = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(expected.st_mode):
            raise ManifestError("manifest must be a regular file (not a symbolic link)")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        file_fd = os.open(path.name, flags, dir_fd=parent_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or not _same_object(expected, before):
                raise ManifestError("manifest changed before reading")
            if before.st_size > 16 * 1024 * 1024:
                raise ManifestError("manifest exceeds 16 MiB limit")
            data = bytearray()
            remaining = before.st_size + 1
            while remaining:
                chunk = os.read(file_fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                data.extend(chunk)
                remaining -= len(chunk)
            after = os.fstat(file_fd)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(data) != before.st_size or any(
                getattr(before, field) != getattr(after, field) for field in stable_fields
            ):
                raise ManifestError("manifest changed while reading")
            try:
                return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object)
            except ValueError as exc:
                raise ManifestError(f"invalid manifest JSON: {exc}") from exc
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "create":
            manifest = build_manifest(args.world)
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0

        manifest = _read_manifest(args.manifest)
        result = verify_manifest(args.world, manifest)
        print(json.dumps(result, sort_keys=True) if args.as_json else _human_report(result))
        return 0 if result["ok"] else 1
    except (ManifestError, OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
