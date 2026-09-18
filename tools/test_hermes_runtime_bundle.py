from __future__ import annotations

import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("bundle_fixture", Path(__file__).resolve().parents[1] / "examples/hermes_runtime_bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.python = self.base / "python-source"
        self.site = self.base / "site"
        (self.python / "bin").mkdir(parents=True)
        (self.python / "bin/python3.11").write_bytes(b"runtime fixture")
        (self.python / "bin/python3.11").chmod(0o755)
        (self.python / "bin/python").symlink_to("python3.11")
        (self.python / "lib/python3.11/site-packages").mkdir(parents=True)
        (self.python / "lib/python3.11/site-packages/must-not-copy").write_text("base package replaced")
        (self.site / "hermes_cli").mkdir(parents=True)
        (self.site / "hermes_cli/main.py").write_text("fixture = True\n")
        (self.site / "hermes_agent-0.19.0.dist-info").mkdir()
        (self.site / "hermes_agent-0.19.0.dist-info/METADATA").write_text("Name: hermes-agent\nVersion: 0.19.0\n\n")
        self.output = self.base / "bundle.tar.gz"

    def build(self):
        return bundle.build(self.python, self.site, self.output)

    def members(self):
        with tarfile.open(self.output, "r:gz") as archive:
            return [(m, archive.extractfile(m).read() if m.isfile() else None) for m in archive]

    def rewrite(self, members):
        target = self.base / "mutated.tar.gz"
        with tarfile.open(target, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for info, raw in members:
                archive.addfile(info, io.BytesIO(raw) if raw is not None else None)
        return target

    def test_exact_bytes_deterministic_archive_and_no_base_packages(self):
        result = self.build()
        self.assertEqual(result["distributions"], [{"name": "hermes-agent", "version": "0.19.0"}])
        other = self.base / "second.tar.gz"
        second = bundle.build(self.python, self.site, other)
        self.assertEqual(result, second)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        members = self.members()
        self.assertFalse(any("must-not-copy" in m.name for m, _ in members))
        alias = next((m, raw) for m, raw in members if m.name == "python/bin/python")
        self.assertTrue(alias[0].isfile())
        self.assertEqual(alias[1], b"runtime fixture")

    def test_bytecode_ignored_and_existing_bundle_never_overwritten(self):
        (self.site / "hermes_cli/__pycache__").mkdir()
        (self.site / "hermes_cli/__pycache__/secret.pyc").write_text("ignored")
        self.build()
        before = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(before, self.output.read_bytes())
        self.assertFalse(any("pycache" in m.name for m, _ in self.members()))

    def test_external_and_directory_symlinks_rejected(self):
        (self.site / "escape").symlink_to(self.python / "bin/python3.11")
        with self.assertRaisesRegex(bundle.BundleFailure, "escapes_tree"):
            self.build()
        (self.site / "escape").unlink()
        (self.site / "directory").symlink_to(self.site / "hermes_cli", target_is_directory=True)
        with self.assertRaisesRegex(bundle.BundleFailure, "directory_symlink"):
            self.build()

    def test_editable_source_reference_rejected(self):
        (self.site / "__editable.hermes.pth").write_text("import outside_finder")
        with self.assertRaisesRegex(bundle.BundleFailure, "editable"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_payload_mutation_missing_and_duplicate_members_rejected(self):
        self.build()
        members = self.members()
        idx = next(i for i, (m, _) in enumerate(members) if m.name == "python/bin/python3.11")
        changed = list(members)
        changed[idx] = (changed[idx][0], b"X" * len(changed[idx][1]))
        with self.assertRaisesRegex(bundle.BundleFailure, "digest_mismatch"):
            bundle.verify(self.rewrite(changed))
        with self.assertRaisesRegex(bundle.BundleFailure, "files_missing"):
            bundle.verify(self.rewrite(members[:idx] + members[idx + 1:]))
        with self.assertRaisesRegex(bundle.BundleFailure, "duplicate"):
            bundle.verify(self.rewrite(members + [members[idx]]))

    def test_links_special_members_and_paths_rejected(self):
        self.build()
        members = self.members()
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            info = tarfile.TarInfo("python/evil")
            info.type, info.mode, info.linkname = kind, 0o644, "/etc/passwd"
            with self.subTest(kind=kind), self.assertRaisesRegex(bundle.BundleFailure, "type_not_allowed"):
                bundle.verify(self.rewrite(members + [(info, None)]))
        for path in ("../escape", "/absolute", "python/../escape", "python\\bad"):
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            with self.subTest(path=path), self.assertRaisesRegex(bundle.BundleFailure, "unsafe_bundle_path"):
                bundle.verify(self.rewrite(members + [(info, b"")]))

    def test_extension_header_rejected_before_large_payload_allocation(self):
        info = tarfile.TarInfo("extension")
        info.type, info.size, info.mode = tarfile.XHDTYPE, 1 << 40, 0o644
        with gzip.open(self.output, "wb") as out:
            out.write(info.tobuf(format=tarfile.GNU_FORMAT))
        with self.assertRaisesRegex(bundle.BundleFailure, "type_not_allowed"):
            bundle.verify(self.output)

    def test_long_installed_filename_kept_and_verified(self):
        name = "a" * 150 + ".py"
        (self.site / "hermes_cli" / name).write_bytes(b"long module fixture")
        # The 100-byte legacy header is deliberately truncated at a slash.
        directory = self.site / ("a" * (100 - len(bundle.PYTHON_SITE) - 2))
        directory.mkdir()
        (directory / name).write_bytes(b"truncated placeholder is not final name")
        self.build()
        self.assertIn(b"long module fixture", [raw for m, raw in self.members() if m.name.endswith(name)])
        bundle.verify(self.output)

    def test_longname_traversal_nested_and_oversized_extensions_rejected(self):
        self.build()
        members = self.members()
        unsafe = tarfile.TarInfo("python/" + "a" * 150 + "/../escape")
        unsafe.mode = 0o644
        with self.assertRaisesRegex(bundle.BundleFailure, "unsafe_bundle_path"):
            bundle.verify(self.rewrite(members + [(unsafe, b"")]))
        for size, nested in ((4097, False), (4, True)):
            info = tarfile.TarInfo("././@LongLink")
            info.type, info.size = tarfile.GNUTYPE_LONGNAME, size
            with gzip.open(self.output, "wb") as out:
                out.write(info.tobuf(format=tarfile.GNU_FORMAT))
                if nested:
                    out.write(b"abc\0" + b"\0" * 508)
                    out.write(info.tobuf(format=tarfile.GNU_FORMAT))
            with self.subTest(size=size), self.assertRaisesRegex(bundle.BundleFailure, "invalid_or_nested_longname"):
                bundle.verify(self.output)

    def test_limits_and_private_output_directory(self):
        with mock.patch.object(bundle, "MAX_TOTAL", 1):
            with self.assertRaisesRegex(bundle.BundleFailure, "size_exceeded"):
                self.build()
        public = self.base / "public"
        public.mkdir(mode=0o755)
        with self.assertRaisesRegex(bundle.BundleFailure, "private_owned"):
            bundle.build(self.python, self.site, public / "bundle")

    def test_directory_payloads_and_unrelated_empty_directories_rejected(self):
        self.build()
        members = self.members()
        item = tarfile.TarInfo("python/unrelated")
        item.type, item.mode = tarfile.DIRTYPE, 0o755
        with self.assertRaisesRegex(bundle.BundleFailure, "undeclared_bundle_directory"):
            bundle.verify(self.rewrite(members + [(item, None)]))
        item.size = 1
        with self.assertRaisesRegex(bundle.BundleFailure, "directory_payload_or_mode_invalid"):
            bundle.verify(self.rewrite(members + [(item, b"x")]))

    def test_symlinked_parent_cannot_place_output_inside_sources(self):
        (self.python / "private").mkdir(mode=0o700)
        link = self.base / "alias"
        link.symlink_to(self.python, target_is_directory=True)
        with self.assertRaisesRegex(bundle.BundleFailure, "outside_sources"):
            bundle.build(self.python, self.site, link / "private/bundle.tar.gz")


if __name__ == "__main__":
    unittest.main()
