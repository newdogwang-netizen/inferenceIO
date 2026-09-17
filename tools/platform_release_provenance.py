#!/usr/bin/env python3
"""Bind a passing connected gate to exact platform source and runtime images."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import stat
import subprocess
import tarfile
from typing import Any, BinaryIO

import connected_soak
import perf_harness


ROOT_FILES = {
    ".dockerignore",
    ".gitignore",
    "Makefile",
    "README.md",
    "go.mod",
    "go.sum",
}
SOURCE_DIRECTORIES = {
    ".github",
    "api",
    "cmd",
    "deploy",
    "docs",
    "internal",
    "migrations",
    "schemas",
}
WEB_ROOT_FILES = {
    "index.html",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "tsconfig.node.json",
    "vite.config.ts",
}
APPLICATION_SERVICES = {"platform-api", "pipeline-worker", "web-console"}
GENERATOR_MODULES = {
    "platform_release_provenance.py": pathlib.Path(__file__).resolve(),
    "connected_soak.py": pathlib.Path(connected_soak.__file__).resolve(),
    "perf_harness.py": pathlib.Path(perf_harness.__file__).resolve(),
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform-root", type=pathlib.Path, default=pathlib.Path("iorec-platform")
    )
    parser.add_argument(
        "--iorec", type=pathlib.Path, default=pathlib.Path("target/release/iorec")
    )
    parser.add_argument("--connected-report", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument(
        "--compose-file", action="append", required=True, type=pathlib.Path
    )
    return parser.parse_args()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def generator_digests() -> dict[str, str]:
    return {
        name: f"sha256:{sha256_file(path)}"
        for name, path in sorted(GENERATOR_MODULES.items())
    }


def checked_regular_file(path: pathlib.Path) -> pathlib.Path:
    resolved = path.expanduser().resolve(strict=True)
    info = path.expanduser().lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"expected a regular non-symlink file: {path}")
    return resolved


def source_paths(root: pathlib.Path) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for name in sorted(ROOT_FILES):
        path = root / name
        if path.is_file() and not path.is_symlink():
            paths.append(path)
    for directory_name in sorted(SOURCE_DIRECTORIES):
        directory = root / directory_name
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"source inventory refuses symlink: {path}")
            if path.is_file():
                paths.append(path)
    web = root / "web"
    for name in sorted(WEB_ROOT_FILES):
        path = web / name
        if path.is_file() and not path.is_symlink():
            paths.append(path)
    for path in sorted((web / "src").rglob("*")):
        if path.is_symlink():
            raise ValueError(f"source inventory refuses symlink: {path}")
        if path.is_file():
            paths.append(path)
    unique = sorted(set(paths))
    if not unique:
        raise RuntimeError("platform source inventory is empty")
    return unique


def source_inventory(root: pathlib.Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    aggregate = hashlib.sha256()
    for path in source_paths(root):
        relative = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        mode = f"{stat.S_IMODE(path.stat().st_mode):04o}"
        size = path.stat().st_size
        aggregate.update(f"{relative}\0{digest}\0{mode}\0{size}\n".encode())
        entries.append(
            {
                "path": relative,
                "sha256": f"sha256:{digest}",
                "mode": mode,
                "bytes": size,
            }
        )
    return {
        "algorithm": "sha256(path-NUL-digest-NUL-mode-NUL-size-LF)",
        "tree_sha256": f"sha256:{aggregate.hexdigest()}",
        "file_count": len(entries),
        "bytes": sum(entry["bytes"] for entry in entries),
        "files": entries,
    }


def hash_tar_member(stream: BinaryIO, expected_name: str) -> tuple[str, int]:
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if (
                pathlib.PurePosixPath(member.name).name != expected_name
                or not member.isfile()
            ):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                break
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: extracted.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
            return digest.hexdigest(), size
    raise RuntimeError(f"container archive did not contain {expected_name}")


def container_file_digest(container: str, path: str) -> dict[str, Any]:
    process = subprocess.Popen(
        ["docker", "cp", f"{container}:{path}", "-"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        digest, size = hash_tar_member(process.stdout, pathlib.PurePosixPath(path).name)
        process.stdout.read()
    finally:
        process.stdout.close()
    stderr = process.stderr.read() if process.stderr is not None else b""
    code = process.wait(timeout=120)
    if code != 0:
        raise RuntimeError(
            f"docker cp failed for {container}:{path}: {stderr[-1000:]!r}"
        )
    return {"path": path, "sha256": f"sha256:{digest}", "bytes": size}


def singleton_container(snapshot: dict[str, Any], service: str) -> dict[str, Any]:
    matches = [
        item for item in snapshot["containers"] if item.get("service") == service
    ]
    if not matches:
        raise RuntimeError(f"runtime snapshot has no {service} container")
    return matches[0]


def mirror_checks(root: pathlib.Path) -> dict[str, bool]:
    migration_root = sorted((root / "migrations").glob("*.sql"))
    migration_embedded = root / "internal/store/migrations"
    schema_root = sorted(
        path for path in (root / "schemas").glob("*.json") if path.is_file()
    )
    schema_embedded = root / "internal/protocol/schemas"
    return {
        "migration_sets_match": {path.name for path in migration_root}
        == {path.name for path in migration_embedded.glob("*.sql")},
        "migration_bytes_match": all(
            path.read_bytes() == (migration_embedded / path.name).read_bytes()
            for path in migration_root
        ),
        "schema_sets_match": {path.name for path in schema_root}
        == {path.name for path in schema_embedded.glob("*.json")},
        "schema_bytes_match": all(
            path.read_bytes() == (schema_embedded / path.name).read_bytes()
            for path in schema_root
        ),
    }


def main() -> int:
    args = arguments()
    root = args.platform_root.expanduser().resolve(strict=True)
    iorec = checked_regular_file(args.iorec)
    connected_path = checked_regular_file(args.connected_report)
    output_parent = args.output.expanduser().parent.resolve(strict=True)
    output = output_parent / args.output.name
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite release provenance: {output}")
    compose_files = [checked_regular_file(path) for path in args.compose_file]
    generator_start = generator_digests()
    compose = connected_soak.compose_base(args.compose_project, compose_files)
    snapshot = connected_soak.compose_runtime_snapshot(compose, compose_files)
    runtime = connected_soak.runtime_provenance(snapshot, snapshot)
    connected = json.loads(connected_path.read_text(encoding="utf-8"))
    inventory = source_inventory(root)
    mirrors = mirror_checks(root)
    api = singleton_container(snapshot, "platform-api")
    worker = singleton_container(snapshot, "pipeline-worker")
    binaries = {
        "platform-api": container_file_digest(api["name"], "/platform-api"),
        "pipeline-worker": container_file_digest(worker["name"], "/pipeline-worker"),
    }
    worker_tools = {
        "tshark": container_file_digest(worker["name"], "/usr/bin/tshark"),
        "file_test": container_file_digest(worker["name"], "/usr/bin/test"),
    }
    worker_version = subprocess.run(
        ["docker", "exec", worker["name"], "/usr/bin/tshark", "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.splitlines()[0]
    dumpcap = subprocess.run(
        [
            "docker",
            "exec",
            worker["name"],
            "/usr/bin/test",
            "-e",
            "/usr/bin/dumpcap",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    generator_end = generator_digests()
    expected_iorec = f"sha256:{sha256_file(iorec)}"
    connected_runtime = connected.get("platform", {}).get("runtime_provenance", {})
    connected_runtime_end = connected_runtime.get("end", {})
    checks = {
        "connected_gate_passed": connected.get("passed") is True,
        "connected_gate_qualified": connected.get("qualified") is True,
        "recorder_hash_matches": connected.get("iorec", {}).get("sha256")
        == expected_iorec,
        "connected_runtime_provenance_passed": connected_runtime.get("passed") is True,
        "connected_images_match_current_runtime": connected_runtime.get("image_ids")
        == runtime.get("image_ids"),
        "connected_compose_config_matches_current": connected_runtime_end.get(
            "compose_config_sha256"
        )
        == snapshot.get("compose_config_sha256"),
        "connected_compose_files_match_current": connected_runtime_end.get(
            "compose_files"
        )
        == snapshot.get("compose_files"),
        "current_runtime_hardened": runtime.get("passed") is True,
        "source_inventory_nonempty": inventory["file_count"] > 0
        and inventory["bytes"] > 0,
        "source_mirrors_match": all(mirrors.values()),
        "application_binaries_nonempty": all(
            artifact["bytes"] > 0 for artifact in binaries.values()
        ),
        "worker_tools_nonempty": all(
            artifact["bytes"] > 0 for artifact in worker_tools.values()
        ),
        "worker_tshark_pinned": worker_version == "TShark (Wireshark) 4.4.18.",
        "worker_has_no_dumpcap": dumpcap.returncode == 1,
        "generator_inputs_unchanged": generator_start == generator_end,
    }
    report = {
        "schema_version": 1,
        "format": "iorec-platform-release-provenance-v1",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passed": all(checks.values()),
        "checks": checks,
        "recorder": {
            "path": str(iorec),
            "sha256": expected_iorec,
            "bytes": iorec.stat().st_size,
        },
        "connected_gate": {
            "path": str(connected_path),
            "sha256": f"sha256:{sha256_file(connected_path)}",
        },
        "platform_source": inventory,
        "generator_sources": generator_start,
        "source_mirror_checks": mirrors,
        "runtime": runtime,
        "container_binaries": binaries,
        "worker": {
            "tshark_version": worker_version,
            "tools": worker_tools,
            "dumpcap_present": dumpcap.returncode == 0,
            "dumpcap_probe_exit_code": dumpcap.returncode,
        },
    }
    if not report["passed"]:
        print(
            json.dumps(
                {
                    "passed": False,
                    "failed_checks": sorted(
                        name for name, passed in checks.items() if not passed
                    ),
                },
                sort_keys=True,
            )
        )
        return 2
    perf_harness.write_report_atomic(output, report)
    print(
        json.dumps(
            {
                "output": str(output),
                "sha256": sha256_file(output),
                "passed": report["passed"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
