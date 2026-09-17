#!/usr/bin/env python3
"""Reproducibly qualify the four exact v1.0 Agent CLI compatibility cells.

The provider is the shipped loopback fixture. Each real CLI runs in the
recorder's rootless proxy-only task network, then the harness independently
verifies encrypted storage and exact task-egress/proxy payload agreement. A
release report is published only if every strict aggregate invariant passes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import signal
import stat
import subprocess
from dataclasses import dataclass
from typing import Any

import perf_harness


EXPECTED_AGENTS = {
    "gemini": {
        "agent": "gemini-cli",
        "version": "0.60.0",
        "executable": pathlib.Path("/tmp/iorec-final-agents/gemini-install/bin/gemini"),
        "canonical_sha256": "fdff028b293149897b948a23b5d8da9e622127182a523be46d82cf267e7816f2",
        "provider": "gemini",
        "runtime": "node",
        "model_attempts": 1,
        "non_model_attempts": 0,
    },
    "codex": {
        "agent": "codex",
        "version": "0.154.0",
        "executable": pathlib.Path(
            "/home/Admin/.codex/packages/standalone/releases/0.154.0-x86_64-unknown-linux-musl/bin/codex"
        ),
        "canonical_sha256": "3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022",
        "provider": "openai",
        "runtime": "native-elf",
        "model_attempts": 1,
        "non_model_attempts": 0,
    },
    "claude": {
        "agent": "claude-code",
        "version": "2.1.273",
        "executable": pathlib.Path("/home/Admin/.local/share/claude/versions/2.1.273"),
        "canonical_sha256": "6c752e2cc7c110c9df15f26d8d134d438c5ae95dbd610efc1a308bf7f9c5f6c1",
        "provider": "anthropic",
        "runtime": "native-elf",
        "model_attempts": 2,
        "non_model_attempts": 1,
    },
    "hermes": {
        "agent": "hermes",
        "version": "0.19.0",
        "executable": pathlib.Path("/home/Admin/.hermes/hermes-agent/venv/bin/hermes"),
        "canonical_sha256": "f248dbd7ccf01dc83187a553a62b476b6877c423f227a469e44138814c7d4d21",
        "provider": "openai",
        "runtime": "python",
        "model_attempts": 1,
        "non_model_attempts": 6,
    },
}

SOURCE_FILES = [
    "Cargo.lock",
    "Cargo.toml",
    "support-matrix.v1.json",
    "src/adapter.rs",
    "src/audit.rs",
    "src/correlation.rs",
    "src/fake_server.rs",
    "src/proxy.rs",
    "src/runner.rs",
    "src/session.rs",
    "src/support_matrix.rs",
    "src/transport_audit.rs",
    "tests/proxy_e2e.rs",
    "tests/runner_e2e.rs",
    "tools/perf_harness.py",
    "tools/real_agent_qualification.py",
]

QUALIFICATION_PATH = "/home/Admin/.local/bin:/usr/local/bin:/usr/bin:/bin"
NODE_PATH = pathlib.Path("/home/Admin/.local/bin/node")
NODE_SHA256 = "81925c0995b5c1427b5d538e6a90ca2fdc4daffb786b09af749beaf7369d4e90"
NODE_VERSION = "v22.22.2"
TSHARK_PATH = pathlib.Path("/usr/bin/tshark")
TSHARK_SHA256 = "261988b660afc78134fb20e4d7cd9d185b26b5e82fbc10713c9af10de6bfa074"
TSHARK_VERSION = "TShark (Wireshark) 4.4.18."


@dataclass(frozen=True)
class AgentRun:
    name: str
    run_dir: pathlib.Path
    audit_path: pathlib.Path
    validation: dict[str, Any]
    audit: dict[str, Any]
    log_path: pathlib.Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iorec", type=pathlib.Path, default=pathlib.Path("target/release/iorec")
    )
    parser.add_argument("--work-dir", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    for name, expected in EXPECTED_AGENTS.items():
        parser.add_argument(
            f"--{name}-executable",
            type=pathlib.Path,
            default=expected["executable"],
            help=f"exact {name} {expected['version']} launcher or executable",
        )
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="archive an existing report by digest before publishing a passing replacement",
    )
    parser.add_argument("--agent-timeout-seconds", type=float, default=300.0)
    return parser.parse_args()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_write(path: pathlib.Path, data: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())


def prepare_paths(args: argparse.Namespace) -> tuple[pathlib.Path, pathlib.Path]:
    work = args.work_dir.expanduser().resolve()
    output_parent = args.output.expanduser().parent.resolve(strict=True)
    output = output_parent / args.output.name
    if output.is_symlink():
        raise ValueError(f"refusing symlink report path: {output}")
    if output.exists() and not args.replace_existing:
        raise FileExistsError(f"refusing to overwrite report: {output}")
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    work.chmod(0o700)
    return work, output


def preflight(
    iorec: pathlib.Path, executables: dict[str, pathlib.Path]
) -> dict[str, dict[str, str]]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("this exact qualification cell requires Linux x86_64")
    if not iorec.is_file() or not os.access(iorec, os.X_OK):
        raise RuntimeError(f"iorec is not executable: {iorec}")
    tshark = TSHARK_PATH
    info = tshark.stat()
    if not tshark.is_file() or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(
            "/usr/bin/tshark must be a root-owned non-writable regular file"
        )
    tshark_digest = sha256_file(tshark)
    if tshark_digest != TSHARK_SHA256:
        raise RuntimeError(f"TShark executable digest changed: {tshark_digest}")
    tshark_version = perf_harness.run_checked(
        [str(tshark), "--version"], timeout=30
    ).stdout.splitlines()[0]
    if tshark_version != TSHARK_VERSION:
        raise RuntimeError(f"TShark version changed: {tshark_version}")
    node = NODE_PATH.resolve(strict=True)
    node_digest = sha256_file(node)
    if node_digest != NODE_SHA256:
        raise RuntimeError(f"Node executable digest changed: {node_digest}")
    node_version = perf_harness.run_checked(
        [str(node), "--version"], timeout=30
    ).stdout.strip()
    if node_version != NODE_VERSION:
        raise RuntimeError(f"Node version changed: {node_version}")
    artifacts: dict[str, dict[str, str]] = {}
    for name, expected in EXPECTED_AGENTS.items():
        executable = executables[name].expanduser().resolve(strict=True)
        digest = sha256_file(executable)
        if digest != expected["canonical_sha256"]:
            raise RuntimeError(f"{name} executable digest changed: {digest}")
        artifacts[name] = {
            "agent": str(expected["agent"]),
            "version": str(expected["version"]),
            "runtime": str(expected["runtime"]),
            "canonical_executable": str(executable),
            "sha256": digest,
        }
    return artifacts


def input_artifacts(
    iorec: pathlib.Path,
    agent_artifacts: dict[str, dict[str, str]],
) -> dict[str, str]:
    source_root = pathlib.Path(__file__).resolve().parent.parent
    snapshot = {
        "iorec_release": sha256_file(iorec),
        "decoder:tshark": sha256_file(TSHARK_PATH),
        "runtime:node": sha256_file(NODE_PATH.resolve(strict=True)),
        **{
            f"agent:{name}": sha256_file(pathlib.Path(artifact["canonical_executable"]))
            for name, artifact in sorted(agent_artifacts.items())
        },
        **{f"source:{path}": sha256_file(source_root / path) for path in SOURCE_FILES},
    }
    return snapshot


def verify_input_artifacts(
    expected: dict[str, str],
    iorec: pathlib.Path,
    agent_artifacts: dict[str, dict[str, str]],
) -> None:
    actual = input_artifacts(iorec, agent_artifacts)
    if actual != expected:
        changed = sorted(
            key
            for key in set(expected) | set(actual)
            if expected.get(key) != actual.get(key)
        )
        raise RuntimeError(f"qualification input changed during execution: {changed}")


def agent_command(name: str, executable: pathlib.Path) -> list[str]:
    prompt = f"Reply with exactly iorec-{name}-qualification-ok and do not use tools."
    if name == "gemini":
        return [
            str(executable),
            "--skip-trust",
            "--approval-mode",
            "plan",
            "--output-format",
            "json",
            "--model",
            "gemini-3.5-flash",
            "--prompt",
            prompt,
        ]
    if name == "codex":
        return [
            str(executable),
            "exec",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "--sandbox",
            "read-only",
            "--color",
            "never",
            "--json",
            "--disable",
            "shell_tool",
            "--disable",
            "unified_exec",
            "--disable",
            "plugins",
            "--model",
            "gpt-5.4-mini",
            prompt,
        ]
    if name == "claude":
        return [
            str(executable),
            "-p",
            "--verbose",
            "--output-format",
            "stream-json",
            "--include-partial-messages",
            "--include-hook-events",
            "--permission-mode",
            "dontAsk",
            "--permission-prompts",
            "none",
            "--tools",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--no-chrome",
            "--setting-sources",
            "user",
            "--prompt-suggestions",
            "false",
            prompt,
        ]
    if name == "hermes":
        return [str(executable), "--ignore-rules", "-t", "", "-z", prompt]
    raise ValueError(f"unsupported Agent: {name}")


def agent_environment(name: str, root: pathlib.Path) -> dict[str, str]:
    home = root / "home"
    home.mkdir(mode=0o700)
    xdg = root / "xdg"
    cache = xdg / "cache"
    config = xdg / "config"
    data = xdg / "data"
    for directory in (xdg, cache, config, data):
        directory.mkdir(mode=0o700)
    environment = {
        "HOME": str(home),
        "PATH": QUALIFICATION_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "COLORTERM": "",
        "NO_COLOR": "1",
        "CI": "1",
        "SHELL": "/bin/sh",
        "USER": "iorec-qualification",
        "LOGNAME": "iorec-qualification",
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "XDG_DATA_HOME": str(data),
    }
    if name == "gemini":
        config = home / ".gemini"
        config.mkdir(mode=0o700)
        private_write(
            config / "settings.json",
            json.dumps(
                {
                    "general": {"enableAutoUpdate": False},
                    "telemetry": {"enabled": False, "logPrompts": False},
                    "skills": {"enabled": False},
                    "mcpServers": {},
                },
                sort_keys=True,
            ),
        )
        environment["GEMINI_CLI_HOME"] = str(home)
        environment["GEMINI_API_KEY"] = "iorec-controlled-provider-key"
    elif name == "codex":
        codex_home = root / "codex-home"
        codex_home.mkdir(mode=0o700)
        environment["CODEX_HOME"] = str(codex_home)
        environment["OPENAI_API_KEY"] = "iorec-controlled-provider-key"
    elif name == "claude":
        claude_config = root / "claude-config"
        claude_config.mkdir(mode=0o700)
        environment["CLAUDE_CONFIG_DIR"] = str(claude_config)
        environment["ANTHROPIC_API_KEY"] = "iorec-controlled-provider-key"
        environment["DISABLE_AUTOUPDATER"] = "1"
        environment["DISABLE_TELEMETRY"] = "1"
    elif name == "hermes":
        hermes_home = root / "hermes-home"
        hermes_home.mkdir(mode=0o700)
        private_write(
            hermes_home / "config.yaml",
            "model:\n"
            "  api_key: iorec-controlled-provider-key\n"
            "  base_url: http://127.0.0.1.invalid/v1\n"
            "  default: gpt-6-astra\n"
            "  provider: custom\n"
            "fallback_providers: []\n"
            "platform_toolsets:\n  cli: []\n"
            "plugins:\n  enabled: []\n",
        )
        environment["HERMES_HOME"] = str(hermes_home)
        environment["OPENAI_API_KEY"] = "iorec-controlled-provider-key"
    return environment


def run_logged(
    command: list[str],
    cwd: pathlib.Path,
    environment: dict[str, str],
    log: pathlib.Path,
    timeout: float,
) -> None:
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb", buffering=0) as destination:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=destination,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=30)
            raise TimeoutError(f"Agent command exceeded {timeout} seconds")
    if code != 0:
        raise subprocess.CalledProcessError(code, command)


def qualify_agent(
    name: str,
    executable: pathlib.Path,
    iorec: pathlib.Path,
    fixture_url: str,
    key_file: pathlib.Path,
    work: pathlib.Path,
    timeout: float,
) -> AgentRun:
    expected = EXPECTED_AGENTS[name]
    root = work / name
    root.mkdir(mode=0o700)
    runs = root / "runs"
    runs.mkdir(mode=0o700)
    cwd = root / "workspace"
    cwd.mkdir(mode=0o700)
    environment = agent_environment(name, root)
    command = [
        str(iorec),
        "run",
        "--runs-dir",
        str(runs),
        "--upstream",
        fixture_url,
        "--provider",
        str(expected["provider"]),
        "--adapter",
        name,
        "--key-file",
        str(key_file),
        "--tls-keylog",
        "--pcap",
        "--task-netns",
        "--",
        *agent_command(name, executable),
    ]
    log = root / "iorec.log"
    run_logged(command, cwd, environment, log, timeout)
    run_dirs = perf_harness.run_directories(runs)
    if len(run_dirs) != 1:
        raise RuntimeError(f"{name} produced {len(run_dirs)} run directories")
    validation = perf_harness.validate_run(iorec, run_dirs[0], key_file)
    audit_path = root / "transport-audit.json"
    audit_command = [
        str(iorec),
        "transport-audit",
        str(run_dirs[0]),
        "--output",
        str(audit_path),
        "--key-file",
        str(key_file),
    ]
    result = subprocess.run(
        audit_command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{name} transport audit failed with {result.returncode}: {result.stderr[-1000:]}"
        )
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    audit_chain = perf_harness.run_checked(
        [str(iorec), "audit-verify", "--runs-dir", str(runs), "--json"], timeout=60
    )
    if json.loads(audit_chain.stdout).get("valid") is not True:
        raise RuntimeError(f"{name} audit chain did not verify")
    return AgentRun(name, run_dirs[0], audit_path, validation, audit, log)


def summarize_run(run: AgentRun) -> dict[str, Any]:
    manifest = run.validation["manifest"]
    coverage = manifest["coverage"]
    counts = manifest["counts"]
    audit = run.audit
    expected = EXPECTED_AGENTS[run.name]
    checks = {
        "target_finished_successfully": manifest["status"] == "finished"
        and manifest["exit_code"] == 0,
        "encrypted_storage_integrity": run.validation["missing_blobs"] == 0
        and run.validation["corrupt_blobs"] == 0
        and run.validation["discarded_tail_bytes"] == 0
        and run.validation["integrity_verifier"].get("passed") is True,
        "no_capture_or_attempt_loss": coverage["capture_drops"] == 0
        and counts["incomplete_attempts"] == 0,
        "transport_complete": audit.get("complete") is True
        and audit.get("schema_version") == 3
        and audit.get("completeness_boundary")
        == "target-network-namespace-ip-transport",
        "exact_payload_agreement": audit.get("payload_diff_passed") is True
        and audit.get("missing_from_wire") == 0
        and audit.get("extra_on_wire") == 0
        and audit.get("ambiguous_signature_groups") == 0,
        "expected_model_attempts": audit.get("proxy_attempts_eligible")
        == expected["model_attempts"]
        and audit.get("matched_attempts") == expected["model_attempts"],
        "expected_non_model_attempts": audit.get("proxy_attempts_non_model_excluded")
        == expected["non_model_attempts"],
        "no_successful_unknown_egress": coverage.get("unknown_egress") == 0,
        "no_unresolved_correlations": coverage.get("unresolved_correlations") == 0,
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "run_id": manifest["run_id"],
        "target_exit_code": manifest["exit_code"],
        "events": counts["events"],
        "blobs": counts["blobs"],
        "logical_tasks": counts["logical_tasks"],
        "logical_inferences": counts["logical_inferences"],
        "transport_attempts": counts["transport_attempts"],
        "completed_attempts": counts["completed_attempts"],
        "model_proxy_attempts": audit["proxy_attempts_eligible"],
        "non_model_proxy_attempts_excluded": audit["proxy_attempts_non_model_excluded"],
        "decoded_streams": audit["decoded_streams"],
        "matched_attempts": audit["matched_attempts"],
        "pcap_records": audit["pcap_records"],
        "capture_drops": coverage["capture_drops"],
        "unknown_egress": coverage["unknown_egress"],
        "unresolved_correlations": coverage["unresolved_correlations"],
        "missing_from_wire": audit["missing_from_wire"],
        "extra_on_wire": audit["extra_on_wire"],
        "ambiguous_signature_groups": audit["ambiguous_signature_groups"],
        "payload_diff_passed": audit["payload_diff_passed"],
        "transport_complete": audit["complete"],
        "transport_audit_gaps": audit["gaps"],
    }


def build_report(
    iorec: pathlib.Path,
    work: pathlib.Path,
    agent_artifacts: dict[str, dict[str, str]],
    runs: list[AgentRun],
    inputs: dict[str, str],
) -> dict[str, Any]:
    live = {run.name: summarize_run(run) for run in runs}
    aggregate = {
        "agents_qualified": sum(int(item["passed"]) for item in live.values()),
        "model_attempts": sum(item["model_proxy_attempts"] for item in live.values()),
        "model_attempts_matched": sum(
            item["matched_attempts"] for item in live.values()
        ),
        "non_model_attempts_excluded_by_semantics": sum(
            item["non_model_proxy_attempts_excluded"] for item in live.values()
        ),
        "missing_from_wire": sum(item["missing_from_wire"] for item in live.values()),
        "extra_on_wire": sum(item["extra_on_wire"] for item in live.values()),
        "ambiguous_signature_groups": sum(
            item["ambiguous_signature_groups"] for item in live.values()
        ),
        "capture_drops": sum(item["capture_drops"] for item in live.values()),
        "successful_unknown_egress": sum(
            item["unknown_egress"] for item in live.values()
        ),
        "unresolved_correlations": sum(
            item["unresolved_correlations"] for item in live.values()
        ),
        "all_transport_audits_complete": all(
            item["transport_complete"] for item in live.values()
        ),
    }
    strict = {
        "four_exact_agents_passed": aggregate["agents_qualified"] == 4,
        "five_model_attempts_matched": aggregate["model_attempts"] == 5
        and aggregate["model_attempts_matched"] == 5,
        "seven_non_model_attempts_semantically_excluded": aggregate[
            "non_model_attempts_excluded_by_semantics"
        ]
        == 7,
        "no_transport_or_correlation_gaps": all(
            aggregate[key] == 0
            for key in (
                "missing_from_wire",
                "extra_on_wire",
                "ambiguous_signature_groups",
                "capture_drops",
                "successful_unknown_egress",
                "unresolved_correlations",
            )
        ),
        "all_transport_audits_complete": aggregate["all_transport_audits_complete"]
        is True,
    }
    binary = iorec.stat()
    return {
        "schema_version": 2,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "subject": "iorec real Agent CLI capture and task-egress transport qualification",
        "status": (
            "qualified_four_exact_agent_cli_cells_transport_complete"
            if all(strict.values())
            else "failed_strict_qualification"
        ),
        "passed": all(strict.values()),
        "strict_checks": strict,
        "qualification_scope": {
            "os": platform.platform(),
            "architecture": platform.machine(),
            "provider_fixture": "shipped controlled loopback HTTP fixture",
            "capture": "immediate task-network pcap for all target IPv4/IPv6 packets",
            "completeness_boundary": "target-network-namespace-ip-transport",
            "comparison": "exact independently decoded wire/proxy body length and SHA-256 multisets",
        },
        "artifacts": {
            "iorec_release": {
                "path": str(iorec),
                "version": perf_harness.run_checked(
                    [str(iorec), "--version"], timeout=30
                ).stdout.strip(),
                "sha256": sha256_file(iorec),
                "bytes": binary.st_size,
                "mode": f"{stat.S_IMODE(binary.st_mode):04o}",
            },
            "agent_executables": agent_artifacts,
            "decoder": {
                "path": str(TSHARK_PATH),
                "version": TSHARK_VERSION,
                "sha256": inputs["decoder:tshark"],
            },
            "runtimes": {
                "gemini_node": {
                    "path": str(NODE_PATH.resolve(strict=True)),
                    "version": NODE_VERSION,
                    "sha256": inputs["runtime:node"],
                }
            },
            "source_files": {path: inputs[f"source:{path}"] for path in SOURCE_FILES},
            "private_evidence_digests": {
                f"{run.name}_manifest_sha256": sha256_file(
                    run.run_dir / "manifest.json"
                )
                for run in runs
            }
            | {
                f"{run.name}_transport_audit_sha256": sha256_file(run.audit_path)
                for run in runs
            }
            | {"private_files_committed": False},
        },
        "live_runs": live,
        "aggregate_result": aggregate,
        "work_dir": str(work),
        "limitations": [
            "Qualification applies only to the exact hashes, versions, Linux x86-64 environment, rootless helper stack, and recorder hash in this report.",
            "The controlled loopback fixture proves request/stream shape and capture agreement, not public-provider availability or provider-hidden state.",
            "Completeness is limited to IP traffic originating inside the target network namespace; same-user Unix IPC and shared host daemons are outside the boundary.",
            "Denied DNS, IPv6, auth, telemetry, update, and unrelated packets are recorded separately and do not count as successful unknown egress.",
        ],
    }


def publish_report(
    output: pathlib.Path, report: dict[str, Any], replace_existing: bool
) -> pathlib.Path | None:
    archived: pathlib.Path | None = None
    if output.is_symlink():
        raise ValueError(f"refusing symlink report path: {output}")
    if output.exists():
        if not replace_existing:
            raise FileExistsError(f"refusing to overwrite report: {output}")
        if not output.is_file():
            raise ValueError(f"existing report is not a regular file: {output}")
        old_digest = sha256_file(output)
        archived = output.with_name(
            f"{output.stem}.superseded-{old_digest[:12]}{output.suffix}"
        )
        if archived.exists() or archived.is_symlink():
            raise FileExistsError(f"refusing to overwrite archived report: {archived}")
        output.replace(archived)
    try:
        perf_harness.write_report_atomic(output, report)
    except Exception:
        if archived is not None and archived.exists() and not output.exists():
            archived.replace(output)
        raise
    return archived


def run(args: argparse.Namespace) -> int:
    if not (30 <= args.agent_timeout_seconds <= 1800):
        raise ValueError("--agent-timeout-seconds must be between 30 and 1800")
    iorec = args.iorec.expanduser().resolve(strict=True)
    work, output = prepare_paths(args)
    executables = {
        name: pathlib.Path(getattr(args, f"{name}_executable")).resolve(strict=True)
        for name in EXPECTED_AGENTS
    }
    artifacts = preflight(iorec, executables)
    inputs = input_artifacts(iorec, artifacts)
    key_file = work / "iorec.key"
    perf_harness.run_checked(
        [str(iorec), "keygen", "--output", str(key_file)], timeout=30
    )
    fake_process, fixture_url = perf_harness.start_fake_server(iorec)
    runs: list[AgentRun] = []
    try:
        for name in ("gemini", "codex", "claude", "hermes"):
            runs.append(
                qualify_agent(
                    name,
                    executables[name],
                    iorec,
                    fixture_url,
                    key_file,
                    work,
                    args.agent_timeout_seconds,
                )
            )
    finally:
        perf_harness.stop_fake_server(fake_process)
    verify_input_artifacts(inputs, iorec, artifacts)
    report = build_report(iorec, work, artifacts, runs, inputs)
    if not report["passed"]:
        failed = work / "failed-report.json"
        perf_harness.write_report_atomic(failed, report)
        print(json.dumps({"passed": False, "diagnostic_report": str(failed)}))
        return 2
    archived = publish_report(output, report, args.replace_existing)
    print(
        json.dumps(
            {
                "passed": True,
                "output": str(output),
                "sha256": sha256_file(output),
                "superseded_report": str(archived) if archived else None,
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    return run(arguments())


if __name__ == "__main__":
    raise SystemExit(main())
