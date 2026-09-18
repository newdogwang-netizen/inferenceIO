"""Freeze an installed Hermes wheel, its dependencies and standalone Python.

Only explicit Python-prefix and site-packages directories are read. Personal
Hermes state is never included. Archives contain regular files/directories only;
in-prefix file symlinks are dereferenced, external/directory links rejected.
No agent or dependency installation code is executed by this utility.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

MAX_FILE = 1 << 30
MAX_TOTAL = 2 << 30
MAX_FILES = 100000
MAX_MANIFEST = 32 << 20
PYTHON_SITE = "python/lib/python3.11/site-packages"


class BundleFailure(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def stamp(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)


def safe_name(name):
    p = PurePosixPath(name)
    if (not name or len(name.encode()) > 4095 or p.is_absolute() or "\\" in name
            or any(c in name for c in "\x00\r\n") or any(x in ("", ".", "..") for x in name.split("/"))
            or (name != "manifest.json" and p.parts[0] != "python")):
        raise BundleFailure("unsafe_bundle_path")
    return name


def sources(python_prefix: Path, site_packages: Path):
    result = {}
    for source, destination in ((python_prefix, "python"), (site_packages, PYTHON_SITE)):
        source = source.resolve(strict=True)
        def unreadable(_):
            raise BundleFailure("source_tree_unreadable")
        for current, dirs, files in os.walk(source, followlinks=False, onerror=unreadable):
            dirs[:] = sorted(n for n in dirs if n != "__pycache__")
            # Replace the standalone Python's own package directory with the
            # exact installed virtualenv package tree, without modifying either.
            if source == python_prefix.resolve() and Path(current) == source / "lib/python3.11":
                dirs[:] = [n for n in dirs if n != "site-packages"]
            if any((Path(current) / n).is_symlink() for n in dirs):
                raise BundleFailure("directory_symlinks_not_supported")
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo")):
                    continue
                path = Path(current) / name
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(source):
                    raise BundleFailure("source_symlink_escapes_tree")
                info = resolved.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                    raise BundleFailure("source_not_regular_or_too_large")
                if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise BundleFailure("elevated_file_mode_not_allowed")
                target = safe_name(destination + "/" + path.relative_to(source).as_posix())
                if target in result:
                    raise BundleFailure("duplicate_bundle_path")
                result[target] = (resolved, stamp(resolved))
                if len(result) > MAX_FILES:
                    raise BundleFailure("bundle_file_count_exceeded")
    if sum(s[1][2] for s in result.values()) > MAX_TOTAL:
        raise BundleFailure("bundle_size_exceeded")
    return result


def installed_versions(site):
    rows = []
    for path in sorted(site.glob("*.dist-info/METADATA")):
        with path.open("rb") as src:
            metadata = BytesParser().parsebytes(src.read(1 << 20), headersonly=True)
        name, version = metadata.get("Name", ""), metadata.get("Version", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) or not re.fullmatch(r"[A-Za-z0-9_.+!-]{1,128}", version):
            raise BundleFailure("invalid_installed_distribution_metadata")
        rows.append({"name": name, "version": version})
    rows = validate_distributions(rows)
    if any(site.glob("*editable*.pth")) or any(site.glob("*.egg-link")):
        raise BundleFailure("editable_hermes_runtime_not_supported")
    return rows


def validate_distributions(rows):
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise BundleFailure("invalid_distribution_list")
    for item in rows:
        if (not isinstance(item, dict) or set(item) != {"name", "version"}
                or not isinstance(item["name"], str) or not isinstance(item["version"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item["name"])
                or not re.fullmatch(r"[A-Za-z0-9_.+!-]{1,128}", item["version"])):
            raise BundleFailure("invalid_installed_distribution_metadata")
    if sum(x["name"].lower().replace("_", "-") == "hermes-agent" for x in rows) != 1:
        raise BundleFailure("exactly_one_installed_hermes_distribution_required")
    return rows


def build(python_prefix, site_packages, output):
    parent = output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise BundleFailure("bundle_output_requires_private_owned_directory")
    if any(output.resolve().is_relative_to(p.resolve()) for p in (python_prefix, site_packages)):
        raise BundleFailure("bundle_output_must_be_outside_sources")
    if not (python_prefix / "bin/python3.11").is_file() or not (site_packages / "hermes_cli/main.py").is_file():
        raise BundleFailure("installed_python311_and_hermes_required")
    initial = sources(python_prefix, site_packages)
    files = []
    for target, (path, before) in sorted(initial.items()):
        digest = sha(path)
        if stamp(path) != before:
            raise BundleFailure("source_changed_during_hash")
        files.append({"path": target, "size": before[2], "sha256": digest,
                      "mode": 0o755 if before[5] & 0o111 else 0o644})
    manifest = {"schema_version": 1, "kind": "iorec-installed-hermes-runtime",
                "python": "python/bin/python3.11", "files": files,
                "distributions": installed_versions(site_packages),
                "transformations": ["bytecode caches omitted", "internal file symlinks dereferenced", "file permissions normalized"],
                "personal_config_sessions_credentials_included": False}
    raw = canonical(manifest)
    if len(raw) > MAX_MANIFEST:
        raise BundleFailure("manifest_too_large")
    # Refuse to overwrite a prior immutable bundle or an unowned output.
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream, gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0, compresslevel=1) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.GNU_FORMAT) as archive:
                item = tarfile.TarInfo("manifest.json")
                item.size, item.mode = len(raw), 0o644
                archive.addfile(item, io.BytesIO(raw))
                dirs = sorted({parent.as_posix() for f in files for parent in PurePosixPath(f["path"]).parents if parent != PurePosixPath(".")})
                for directory in dirs:
                    item = tarfile.TarInfo(safe_name(directory))
                    item.type, item.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(item)
                for f in files:
                    path, before = initial[f["path"]]
                    if stamp(path) != before:
                        raise BundleFailure("source_changed_before_archive")
                    item = tarfile.TarInfo(f["path"])
                    item.size, item.mode = f["size"], f["mode"]
                    with path.open("rb") as src:
                        archive.addfile(item, src)
                    if stamp(path) != before:
                        raise BundleFailure("source_changed_during_archive")
        if sources(python_prefix, site_packages) != initial:
            raise BundleFailure("source_tree_changed_during_archive")
        return verify(output)
    except BaseException:
        # Only this invocation's exclusively-created partial output is removed.
        output.unlink(missing_ok=True)
        raise


class StrictTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # Installed wheels contain basenames longer than USTAR's 100 bytes.
        # Permit one bounded GNU longname, validating the resolved name AFTER
        # tarfile merges it. Reject recursive extensions before they recurse.
        if self.type == tarfile.GNUTYPE_LONGNAME:
            if not 1 <= self.size <= 4096 or getattr(archive, "_iorec_longname_pending", False):
                raise BundleFailure("invalid_or_nested_longname")
            archive._iorec_longname_pending = True
            try:
                member = super()._proc_member(archive)
                safe_name(member.name.rstrip("/") if member.isdir() else member.name)
                return member
            finally:
                archive._iorec_longname_pending = False
        # Reject PAX, longlink, sparse and links BEFORE extension processing.
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise BundleFailure("bundle_member_type_not_allowed")
        if not 0 <= self.size <= MAX_FILE or self.mode not in (0o644, 0o755):
            raise BundleFailure("bundle_member_size_or_mode_invalid")
        if self.isdir() and (self.size != 0 or self.mode != 0o755):
            raise BundleFailure("bundle_directory_payload_or_mode_invalid")
        # With GNU longname this header contains only a truncated placeholder,
        # which may end in the middle of a path component. The outer extension
        # validates the complete name before yielding any member to the caller.
        if not getattr(archive, "_iorec_longname_pending", False):
            safe_name(self.name.rstrip("/") if self.isdir() else self.name)
        return super()._proc_member(archive)


def verify(path):
    before = stamp(path)
    if not stat.S_ISREG(before[5]) or before[2] > MAX_FILE:
        raise BundleFailure("bundle_not_regular_or_too_large")
    with tarfile.open(path, "r|gz", tarinfo=StrictTarInfo) as archive:
        first = archive.next()
        if first is None or first.name != "manifest.json" or not first.isfile() or first.size > MAX_MANIFEST:
            raise BundleFailure("first_bundle_member_must_be_manifest")
        raw = archive.extractfile(first).read()
        manifest = json.loads(raw)
        if manifest.get("schema_version") != 1 or manifest.get("kind") != "iorec-installed-hermes-runtime":
            raise BundleFailure("unsupported_bundle_manifest")
        validate_distributions(manifest.get("distributions"))
        if manifest.get("python") != "python/bin/python3.11":
            raise BundleFailure("unsupported_bundle_python_path")
        expected = {}
        for item in manifest["files"]:
            name = safe_name(item["path"])
            if name == "manifest.json" or name in expected:
                raise BundleFailure("duplicate_manifest_file")
            expected[name] = item
            if len(expected) > MAX_FILES:
                raise BundleFailure("bundle_file_count_exceeded")
        expected_dirs = {p.as_posix() for name in expected for p in PurePosixPath(name).parents if p != PurePosixPath(".")}
        seen, total, entries = set(), 0, 0
        for item in archive:
            if item is first:
                continue
            entries += 1
            if entries > MAX_FILES * 2 or item.name in seen:
                raise BundleFailure("duplicate_or_excess_bundle_members")
            seen.add(item.name)
            if item.isdir():
                if item.name not in expected_dirs:
                    raise BundleFailure("undeclared_bundle_directory")
                continue
            declared = expected.get(item.name)
            if declared is None or item.size != declared["size"] or item.mode != declared["mode"]:
                raise BundleFailure("undeclared_or_mismatched_bundle_member")
            total += item.size
            if total > MAX_TOTAL:
                raise BundleFailure("bundle_size_exceeded")
            h = hashlib.sha256()
            with archive.extractfile(item) as src:
                for block in iter(lambda: src.read(1 << 20), b""):
                    h.update(block)
            if h.hexdigest() != declared["sha256"]:
                raise BundleFailure("bundle_payload_digest_mismatch")
        if not set(expected).issubset(seen):
            raise BundleFailure("bundle_files_missing")
        if manifest.get("python") not in expected or PYTHON_SITE + "/hermes_cli/main.py" not in expected:
            raise BundleFailure("bundle_python_or_hermes_missing")
    digest = sha(path)
    if stamp(path) != before:
        raise BundleFailure("bundle_changed_while_verifying")
    return {"archive_sha256": digest, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "files": len(expected), "uncompressed_bytes": total,
            "distributions": manifest["distributions"], "scope": "installed_runtime_not_personal_hermes_state"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=("build", "verify"))
    p.add_argument("--python-prefix", type=Path)
    p.add_argument("--site-packages", type=Path)
    p.add_argument("--archive", required=True, type=Path)
    args = p.parse_args()
    try:
        if args.operation == "build":
            if args.python_prefix is None or args.site_packages is None:
                raise BundleFailure("explicit_python_prefix_and_site_packages_required")
            result = build(args.python_prefix, args.site_packages, args.archive)
        else:
            result = verify(args.archive)
        print(json.dumps({"passed": True, **result}, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"passed": False, "error": str(error) if isinstance(error, BundleFailure) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
