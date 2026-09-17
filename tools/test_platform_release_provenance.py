#!/usr/bin/env python3

from __future__ import annotations

import io
import pathlib
import tarfile
import tempfile
import unittest

import platform_release_provenance as provenance


class PlatformReleaseProvenanceTests(unittest.TestCase):
    def test_tar_member_digest_is_exact(self) -> None:
        content = b"exact-platform-binary"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo("platform-api")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        stream.seek(0)
        digest, size = provenance.hash_tar_member(stream, "platform-api")
        self.assertEqual(
            digest,
            "1db12a05aeff2b5221e4f86b4988f6ceef548a551a17302c8b5ed8c76ddeaf38",
        )
        self.assertEqual(size, len(content))

    def test_source_inventory_and_mirrors_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "go.mod").write_text("module test\n", encoding="utf-8")
            (root / "internal/store/migrations").mkdir(parents=True)
            (root / "internal/protocol/schemas").mkdir(parents=True)
            (root / "migrations").mkdir()
            (root / "schemas").mkdir()
            (root / "web/src").mkdir(parents=True)
            (root / "web/src/main.ts").write_text("export {};\n", encoding="utf-8")
            (root / "migrations/0001.sql").write_text("select 1;\n", encoding="utf-8")
            (root / "internal/store/migrations/0001.sql").write_text(
                "select 1;\n", encoding="utf-8"
            )
            (root / "schemas/event.json").write_text("{}\n", encoding="utf-8")
            (root / "internal/protocol/schemas/event.json").write_text(
                "{}\n", encoding="utf-8"
            )
            first = provenance.source_inventory(root)
            second = provenance.source_inventory(root)
            self.assertEqual(first, second)
            self.assertGreater(first["file_count"], 0)
            self.assertTrue(all(provenance.mirror_checks(root).values()))


if __name__ == "__main__":
    unittest.main()
