#!/usr/bin/env python3
"""Unit tests for the TrustDBAnchorV1 reproducible build boundary."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_anchor_contract.py")
SPEC = importlib.util.spec_from_file_location("build_anchor_contract", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class ArchiveExtractionTests(unittest.TestCase):
    def make_archive(self, path: Path, member: tarfile.TarInfo, content: bytes = b"") -> None:
        with tarfile.open(path, "w:gz") as archive:
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)

    def test_extracts_single_regular_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "compiler.tar.gz"
            member = tarfile.TarInfo("release/solc")
            member.size = 4
            member.mode = 0o644
            self.make_archive(archive, member, b"solc")
            compiler = BUILD.extract_compiler_archive(archive, root / "output")
            self.assertEqual(compiler.read_bytes(), b"solc")
            self.assertNotEqual(compiler.stat().st_mode & 0o111, 0)

    def test_rejects_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "compiler.tar.gz"
            member = tarfile.TarInfo("../solc")
            member.size = 4
            self.make_archive(archive, member, b"solc")
            with self.assertRaises(BUILD.BuildError):
                BUILD.extract_compiler_archive(archive, root / "output")

    def test_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "compiler.tar.gz"
            member = tarfile.TarInfo("solc")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../outside"
            self.make_archive(archive, member)
            with self.assertRaises(BUILD.BuildError):
                BUILD.extract_compiler_archive(archive, root / "output")


if __name__ == "__main__":
    unittest.main()
