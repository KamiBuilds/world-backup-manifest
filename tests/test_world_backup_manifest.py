import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import world_backup_manifest as wbm


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI = PROJECT_ROOT / "world_backup_manifest.py"


class BuildManifestTests(unittest.TestCase):
    def test_build_manifest_hashes_files_in_stable_path_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            (root / "region").mkdir(parents=True)
            (root / "level.dat").write_bytes(b"level-data")
            (root / "region" / "r.0.0.mca").write_bytes(b"chunk-data")

            manifest = wbm.build_manifest(root)

            self.assertEqual(manifest["format_version"], 1)
            self.assertEqual(manifest["algorithm"], "sha256")
            self.assertEqual(
                [entry["path"] for entry in manifest["files"]],
                ["level.dat", "region/r.0.0.mca"],
            )
            self.assertEqual(
                manifest["files"][0],
                {
                    "path": "level.dat",
                    "size": 10,
                    "sha256": hashlib.sha256(b"level-data").hexdigest(),
                },
            )

    def test_build_manifest_rejects_symlinks_instead_of_following_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            outside = Path(tmp) / "private.txt"
            outside.write_text("not part of backup", encoding="utf-8")
            (root / "escape").symlink_to(outside)

            with self.assertRaisesRegex(wbm.ManifestError, "symbolic link"):
                wbm.build_manifest(root)

    def test_build_manifest_rejects_symlinked_path_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_parent = Path(tmp) / "real"
            world = real_parent / "world"
            world.mkdir(parents=True)
            (world / "level.dat").write_bytes(b"data")
            linked_parent = Path(tmp) / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaisesRegex(wbm.ManifestError, "safe directory"):
                wbm.build_manifest(linked_parent / "world")

    def test_build_manifest_rejects_special_files(self):
        if not hasattr(__import__("os"), "mkfifo"):
            self.skipTest("FIFOs are not supported on this platform")
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.mkfifo(root / "server.pipe")

            with self.assertRaisesRegex(wbm.ManifestError, "regular file"):
                wbm.build_manifest(root)

    @unittest.skipUnless(hasattr(__import__("os"), "mkfifo"), "requires POSIX FIFOs")
    def test_regular_file_swapped_for_fifo_fails_promptly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "victim.dat").write_bytes(b"synthetic")
            script = """
import os, sys
from pathlib import Path
import world_backup_manifest as wbm
original_open = os.open
def swap_before_open(path, flags, *args, **kwargs):
    if path == 'victim.dat':
        os.unlink(path, dir_fd=kwargs['dir_fd'])
        os.mkfifo(path, dir_fd=kwargs['dir_fd'])
    return original_open(path, flags, *args, **kwargs)
os.open = swap_before_open
try:
    wbm.build_manifest(Path(sys.argv[1]))
except wbm.ManifestError as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(2)
sys.exit(0)
"""
            try:
                result = subprocess.run(
                    [sys.executable, "-c", script, str(root)],
                    cwd=PROJECT_ROOT, text=True, capture_output=True, timeout=3,
                )
            except subprocess.TimeoutExpired:
                self.fail("regular-file to FIFO swap blocked before validation")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("backup changed during scan", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_growing_regular_file_is_rejected_with_a_bounded_read(self):
        import os
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "growing.dat"
            victim.write_bytes(b"data")
            original_read = os.read
            consumed = 0

            def append_before_read(fd, count):
                nonlocal consumed
                with victim.open("ab") as handle:
                    handle.write(b"growth")
                chunk = original_read(fd, count)
                consumed += len(chunk)
                if consumed > 5:
                    self.fail("hashing exceeded initial file size plus one byte")
                return chunk

            with patch.object(wbm.os, "read", append_before_read):
                with self.assertRaisesRegex(wbm.ManifestError, "changed while hashing"):
                    wbm.build_manifest(root)

    def test_build_rejects_names_that_cannot_round_trip_through_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad\\name.dat").write_bytes(b"synthetic")
            with self.assertRaisesRegex(wbm.ManifestError, "unsupported filename"):
                wbm.build_manifest(root)

    def test_build_manifest_requires_a_directory(self):
        missing = Path("this-world-does-not-exist")

        with self.assertRaisesRegex(wbm.ManifestError, "directory"):
            wbm.build_manifest(missing)


class VerifyManifestTests(unittest.TestCase):
    def test_verify_manifest_reports_missing_modified_and_unexpected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            (root / "same.dat").write_bytes(b"same")
            (root / "changed.dat").write_bytes(b"before")
            (root / "missing.dat").write_bytes(b"gone soon")
            manifest = wbm.build_manifest(root)

            (root / "changed.dat").write_bytes(b"after")
            (root / "missing.dat").unlink()
            (root / "new.dat").write_bytes(b"new")

            result = wbm.verify_manifest(root, manifest)

            self.assertFalse(result["ok"])
            self.assertEqual(result["matched"], 1)
            self.assertEqual(result["missing"], ["missing.dat"])
            self.assertEqual(result["modified"], ["changed.dat"])
            self.assertEqual(result["unexpected"], ["new.dat"])

    def test_verify_manifest_accepts_unchanged_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "level.dat").write_bytes(b"stable")
            manifest = wbm.build_manifest(root)

            result = wbm.verify_manifest(root, manifest)

            self.assertEqual(
                result,
                {
                    "ok": True,
                    "matched": 1,
                    "missing": [],
                    "modified": [],
                    "unexpected": [],
                },
            )


    def test_verify_manifest_rejects_unsafe_or_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "level.dat").write_bytes(b"stable")
            valid_entry = wbm.build_manifest(root)["files"][0]

            for bad_path in ("../escape", "/absolute", ".", "level.dat"):
                manifest = {
                    "format_version": 1,
                    "algorithm": "sha256",
                    "files": [valid_entry, {**valid_entry, "path": bad_path}],
                }
                with self.subTest(path=bad_path):
                    with self.assertRaises(wbm.ManifestError):
                        wbm.verify_manifest(root, manifest)

    def test_verify_manifest_rejects_unknown_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {"format_version": 99, "algorithm": "sha256", "files": []}

            with self.assertRaisesRegex(wbm.ManifestError, "format"):
                wbm.verify_manifest(root, manifest)


    def test_verify_manifest_rejects_boolean_version_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "level.dat").write_bytes(b"stable")
            entry = wbm.build_manifest(root)["files"][0]
            bad_manifests = [
                {"format_version": True, "algorithm": "sha256", "files": [entry]},
                {
                    "format_version": 1,
                    "algorithm": "sha256",
                    "files": [{**entry, "note": "not part of format"}],
                },
            ]

            for manifest in bad_manifests:
                with self.subTest(manifest=manifest):
                    with self.assertRaises(wbm.ManifestError):
                        wbm.verify_manifest(root, manifest)


class CliTests(unittest.TestCase):
    def test_create_writes_manifest_json_to_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            (root / "level.dat").write_bytes(b"world")

            result = subprocess.run(
                [sys.executable, str(CLI), "create", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["format_version"], 1)
            self.assertEqual([entry["path"] for entry in manifest["files"]], ["level.dat"])
            self.assertEqual(result.stderr, "")

    def test_create_returns_status_two_for_symlink_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            loop = Path(tmp) / "loop"
            loop.symlink_to("loop")

            result = subprocess.run(
                [sys.executable, str(CLI), "create", str(loop)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("error:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_verify_json_uses_exit_status_to_signal_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            tracked = root / "level.dat"
            tracked.write_bytes(b"before")
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(json.dumps(wbm.build_manifest(root)), encoding="utf-8")

            clean = subprocess.run(
                [sys.executable, str(CLI), "verify", str(root), str(manifest_path), "--json"],
                text=True,
                capture_output=True,
                check=False,
            )
            tracked.write_bytes(b"after")
            drifted = subprocess.run(
                [sys.executable, str(CLI), "verify", str(root), str(manifest_path), "--json"],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertTrue(json.loads(clean.stdout)["ok"])
            self.assertEqual(drifted.returncode, 1, drifted.stderr)
            self.assertEqual(json.loads(drifted.stdout)["modified"], ["level.dat"])


    def test_verify_returns_status_two_for_unreadable_manifest_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            manifest_dir = Path(tmp) / "manifest-dir"
            manifest_dir.mkdir()
            invalid_utf8 = Path(tmp) / "invalid.json"
            invalid_utf8.write_bytes(b"\xff")

            for manifest_path in (manifest_dir, invalid_utf8):
                result = subprocess.run(
                    [sys.executable, str(CLI), "verify", str(root), str(manifest_path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                with self.subTest(path=manifest_path.name):
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("error:", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(hasattr(__import__("os"), "mkfifo"), "requires POSIX FIFOs")
    def test_verify_rejects_fifo_manifest_without_blocking(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            manifest_path = Path(tmp) / "manifest.pipe"
            os.mkfifo(manifest_path)
            try:
                result = subprocess.run(
                    [sys.executable, str(CLI), "verify", str(root), str(manifest_path)],
                    text=True, capture_output=True, timeout=3,
                )
            except subprocess.TimeoutExpired:
                self.fail("verify blocked opening a FIFO manifest")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("regular file", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_verify_rejects_oversized_manifest_before_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            manifest_path = Path(tmp) / "oversized.json"
            with manifest_path.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)
            result = subprocess.run(
                [sys.executable, str(CLI), "verify", str(root), str(manifest_path)],
                text=True, capture_output=True, timeout=3,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("manifest exceeds 16 MiB limit", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_verify_returns_status_two_for_oversized_json_integer(self):
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            manifest_path = Path(tmp) / "large-integer.json"
            manifest_path.write_text(
                '{"format_version":' + "9" * 5000 + ',"algorithm":"sha256","files":[]}',
                encoding="utf-8",
            )
            env = {**os.environ, "PYTHONINTMAXSTRDIGITS": "4300"}
            for options in ([], ["--json"]):
                with self.subTest(options=options):
                    result = subprocess.run(
                        [sys.executable, str(CLI), "verify", str(root), str(manifest_path), *options],
                        env=env, text=True, capture_output=True, timeout=3,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("error:", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_commands_fail_closed_without_safe_filesystem_support(self):
        import contextlib
        import io
        import os

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "empty.json"
            manifest_path.write_text('{"format_version":1,"algorithm":"sha256","files":[]}')
            nonblock = os.O_NONBLOCK
            del os.O_NONBLOCK
            try:
                for args in (["create", str(root)], ["verify", str(root), str(manifest_path)]):
                    with self.subTest(command=args[0]):
                        stderr = io.StringIO()
                        with contextlib.redirect_stderr(stderr):
                            try:
                                status = wbm.main(args)
                            except AttributeError:
                                self.fail("missing safe filesystem support escaped as AttributeError")
                        self.assertEqual(status, 2)
                        self.assertIn("platform lacks safe", stderr.getvalue())
            finally:
                os.O_NONBLOCK = nonblock

    def test_verify_rejects_duplicate_json_object_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "world"
            root.mkdir()
            manifest_path = Path(tmp) / "duplicate.json"
            manifest_path.write_text(
                '{"format_version":1,"algorithm":"sha256","files":[{}],"files":[]}',
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(CLI), "verify", str(root), str(manifest_path)],
                text=True, capture_output=True, timeout=3,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("duplicate JSON key", result.stderr)

    def test_human_report_escapes_terminal_control_characters(self):
        result = {
            "ok": False,
            "matched": 0,
            "missing": ["evil\nUNEXPECTED: forged"],
            "modified": [],
            "unexpected": [],
        }

        report = wbm._human_report(result)

        self.assertNotIn("evil\n", report)
        self.assertIn(r"evil\nUNEXPECTED", report)


if __name__ == "__main__":
    unittest.main()
