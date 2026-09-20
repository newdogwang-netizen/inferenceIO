"""Bounded input identity checks for fresh Harbor audit experiments.

This is drift detection, not attestation against a malicious host. Harbor's
own package and upload bytes are pinned; its transitive Python dependencies,
Docker daemon and apt-resolved container tooling are NOT qualified by this
identity alone. No provider call is made here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tomllib

from harbor_task_network import task_network_input

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 1 << 30
MAX_TREE_BYTES = 2 << 30
MAX_TREE_FILES = 100000


class InputFailure(Exception):
    """Fixed error codes only; never propagate a subprocess's raw output."""


def pinned_image_reference(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]{0,200}@sha256:[0-9a-f]{64}", value):
        raise InputFailure("task_image_requires_immutable_repository_digest")
    return value


def image_compose(reference):
    return {"services": {"main": {"image": pinned_image_reference(reference), "pull_policy": "never"}}}


def docker_image_identity(reference):
    if not isinstance(reference, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,300}", reference):
        raise InputFailure("invalid_task_image_reference")
    # Do not expose Config.Env or other potentially sensitive image metadata.
    fmt = '{"id":{{json .Id}},"digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}'
    result = subprocess.run(["docker", "image", "inspect", reference, "--format", fmt],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False)
    if result.returncode or len(result.stdout) > 32768:
        raise InputFailure("task_image_not_available_locally")
    info = json.loads(result.stdout)
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}", info.get("id", ""))
            or info.get("os") != "linux" or info.get("architecture") != "amd64"):
        raise InputFailure("task_image_requires_linux_amd64")
    return info


def task_image_input(task: Path, reference: str):
    reference = pinned_image_reference(reference)
    with (task / "task.toml").open("rb") as src:
        raw = src.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise InputFailure("task_config_too_large")
    config = tomllib.loads(raw.decode())
    # A shared overlay would also override a separate verifier's main service.
    # Do not silently replace its independently specified image.
    if config.get("verifier", {}).get("environment_mode", "same") not in ("same", "shared"):
        raise InputFailure("task_image_override_requires_shared_verifier")
    if any((task / "environment" / name).exists() for name in (
            "docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml")):
        raise InputFailure("task_image_override_requires_single_service_task")
    declared = config.get("environment", {}).get("docker_image")
    actual = docker_image_identity(reference)
    if reference not in (actual.get("digests") or []):
        raise InputFailure("task_image_repository_digest_not_present")
    if docker_image_identity(declared)["id"] != actual["id"]:
        raise InputFailure("task_image_override_differs_from_published_image")
    return {"declared_reference": declared, "pinned_reference": reference,
            "image_id": actual["id"], "os": actual["os"], "architecture": actual["architecture"],
            "scope": "single_main_service_shared_verifier_no_task_file_changes"}


def file_identity(path: Path):
    # Resolve system-library symlinks, but record the resolved destination too.
    resolved = path.resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise InputFailure("input_not_regular_or_too_large")
        h, count = hashlib.sha256(), 0
        for block in iter(lambda: stream.read(1 << 20), b""):
            count += len(block)
            if count > MAX_FILE_BYTES:
                raise InputFailure("input_file_limit_exceeded")
            h.update(block)
        after = os.fstat(stream.fileno())
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)
    if signature(before) != signature(after) or signature(after) != signature(resolved.stat()):
        raise InputFailure("input_changed_while_hashing")
    return {"path": str(resolved), "sha256": h.hexdigest(), "bytes": count,
            "mode": stat.S_IMODE(after.st_mode)}


def tree_identity(root: Path, *, ignored_names=()):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise InputFailure("input_tree_not_directory")
    h, count, total = hashlib.sha256(), 0, 0
    # os.walk never traverses a symlink. Explicitly reject even dangling ones.
    def unreadable(_):
        raise InputFailure("input_tree_unreadable")
    for current, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        dirs[:] = sorted(name for name in dirs if name not in ignored_names)
        for name in sorted(dirs + [n for n in files if n not in ignored_names]):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise InputFailure("input_tree_symlinks_not_allowed")
            if path.is_dir():
                item = {"path": relative, "directory": True, "mode": stat.S_IMODE(path.stat().st_mode)}
            else:
                item = file_identity(path)
                item["path"] = relative
                total += item["bytes"]
            count += 1
            if count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                raise InputFailure("input_tree_limit_exceeded")
            h.update(json.dumps(item, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    if count == 0:
        raise InputFailure("input_tree_empty")
    return {"path": str(root), "sha256": h.hexdigest(), "entries": count, "bytes": total,
            "ignored_names": sorted(ignored_names)}


def harbor_environment():
    # An inherited PYTHONPATH could shadow either Harbor or our audit profile.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("IOREC_HARBOR_", "PYTHON"))}
    env["PYTHONPATH"] = str(ROOT / "examples")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def harbor_runtime(launcher: Path | None = None):
    launcher = (launcher or Path(shutil.which("harbor") or "/missing/harbor")).resolve(strict=True)
    with launcher.open("rb") as stream:
        first = stream.readline(512).decode("ascii", errors="strict").strip()
    # Do not guess which interpreter /usr/bin/env or a shell wrapper will use.
    if not re.fullmatch(r"#!/[^\s]+/python[0-9.]*", first):
        raise InputFailure("harbor_requires_explicit_python_shebang")
    interpreter = Path(first[2:]).resolve(strict=True)
    probe = """
import importlib.metadata, importlib.util, json, pathlib, sys
sys.path[0] = sys.argv[1]
d = importlib.metadata.distribution('harbor')
s = importlib.util.find_spec('harbor')
p = pathlib.Path(d.locate_file('harbor')).resolve()
if s is None or pathlib.Path(s.origin).resolve().parent != p:
    raise RuntimeError('harbor_import_shadowed')
print(json.dumps({'version': d.version, 'package': str(p)}))
"""
    result = subprocess.run([str(interpreter), "-c", probe, str(launcher.parent)],
                            env=harbor_environment(), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
                            cwd=ROOT / "examples", check=False)
    if result.returncode or len(result.stdout) > 8192:
        raise InputFailure("harbor_runtime_probe_failed")
    info = json.loads(result.stdout)
    if not re.fullmatch(r"[0-9][a-zA-Z0-9.+_-]{0,63}", info["version"]):
        raise InputFailure("invalid_harbor_package_version")
    return {"launcher": file_identity(launcher), "interpreter": file_identity(interpreter),
            "package_version": info["version"],
            "package": tree_identity(Path(info["package"]), ignored_names=("__pycache__",)),
            "scope": "launcher_interpreter_harbor_package_not_transitive_python_or_OS_dependencies"}


def audit_definitions():
    # Load exactly this checkout's stdlib-only upload definition. No inherited
    # Python module search path is used to resolve it.
    import importlib.util
    path = ROOT / "examples/harbor_audit_inputs.py"
    spec = importlib.util.spec_from_file_location("iorec_audit_inputs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def measurement_definitions():
    import importlib.util
    path = ROOT / "examples/harbor_audit_measure.py"
    spec = importlib.util.spec_from_file_location("iorec_audit_measure", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def task_reported_name(task: Path):
    """Harbor reports [task].name verbatim, not necessarily the folder name."""
    with (task / "task.toml").open("rb") as source:
        raw = source.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise InputFailure("task_config_too_large")
    config = tomllib.loads(raw.decode())
    name = config.get("task", {}).get("name", task.name)
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.~/-]{0,255}", name):
        raise InputFailure("invalid_reported_task_name")
    return name


def fresh_identity(args, launcher: Path | None = None):
    module = audit_definitions()
    path = ROOT / "examples/harbor_audit_inputs.py"
    agent = getattr(args, "agent", "codex")
    recording_mode = getattr(args, "recording_mode", "on")
    upstream = getattr(args, "upstream", "") or module.AGENTS[agent]["upstream"]
    bundle = getattr(args, "hermes_bundle", None) if agent == "hermes" else None
    executable = ROOT / "examples/harbor-audit-hermes" if agent == "hermes" else getattr(args, agent)
    uploads = module.native_uploads(agent=agent, executable=executable,
                                    iorec=args.iorec, key=args.key_file, hermes_bundle=bundle)
    result = {"task": tree_identity(args.task, ignored_names=(".git",)),
            "agent": agent, "upstream": module.upstream_url(upstream), "recording_mode": recording_mode,
            "cli_wrapper_sha256": hashlib.sha256(module.cli_wrapper(agent, upstream, recording_mode).encode()).hexdigest(),
            "uploads": {remote: file_identity(local) for local, remote in uploads.items()
                        if remote != "/tmp/iorec.key"},
            "harbor": harbor_runtime(launcher),
            "controller": {str(p.relative_to(ROOT)): file_identity(p) for p in (
                Path(__file__), ROOT / "tools/harbor_audit_workflow.py", ROOT / "tools/harbor_task_network.py", path,
                ROOT / "examples/harbor_iorec_audit_base.py",
                ROOT / ("examples/harbor_iorec_" + agent + "_audit.py"),
                ROOT / "examples/harbor-audit-compose.yaml")}}
    result["task"]["harbor_name"] = task_reported_name(args.task)
    if agent == "hermes":
        import importlib.util
        verifier_path = ROOT / "examples/hermes_runtime_bundle.py"
        spec = importlib.util.spec_from_file_location("iorec_runtime_bundle", verifier_path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        result["hermes_runtime"] = verifier.verify(bundle)
        if result["hermes_runtime"]["archive_sha256"] != result["uploads"]["/tmp/iorec-hermes-runtime.tar.gz"]["sha256"]:
            raise InputFailure("hermes_bundle_changed_during_preflight")
        result["controller"][str(verifier_path.relative_to(ROOT))] = file_identity(verifier_path)
    if getattr(args, "task_image", None):
        result["task_image_override"] = task_image_input(args.task, args.task_image)
    if getattr(args, "task_network_subnet", None):
        result["task_network_override"] = task_network_input(args.task, args.task_network_subnet)
    if getattr(args, "experiment_plan", None):
        for name in ("m3_experiment_plan.py", "m3_trial_ledger.py"):
            validator = ROOT / "tools" / name
            result["controller"][str(validator.relative_to(ROOT))] = file_identity(validator)
    return result
