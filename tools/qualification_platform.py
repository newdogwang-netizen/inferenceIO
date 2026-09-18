#!/usr/bin/env python3
"""Private, authenticated, isolated Compose instance for destructive soak tests.

Never reuses the browsing platform's database or credentials. No delete/down
command is provided: reports and test evidence remain available for inspection.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

import connected_soak
from harbor_audit_workflow import atomic_json, private_path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [ROOT / "iorec-platform/deploy/compose.yaml", ROOT / "iorec-platform/deploy/compose.qualify.yaml"]


def private_text(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(value + "\n")
        out.flush()
        os.fsync(out.fileno())


def environment(settings):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("IOREC_", "COMPOSE_", "POSTGRES_", "OBJECT_STORE_", "DATABASE_"))}
    env.update(settings["environment"])
    env["COMPOSE_DISABLE_ENV_FILE"] = "1"
    return env


def initialize(args):
    if not re.fullmatch(r"iorec-qual-[a-z0-9-]{1,36}", args.project):
        raise ValueError("dedicated iorec-qual project required")
    if not 1024 <= args.api_port <= 65535 or not 1024 <= args.web_port <= 65535 or args.api_port == args.web_port:
        raise ValueError("distinct unprivileged ports required")
    for kind in ("container", "volume", "network"):
        command = ["docker", kind, "ls", "-q"]
        if kind == "container":
            command.append("-a")  # Stopped containers still belong to their owner.
        result = subprocess.check_output([*command, "--filter", f"label=com.docker.compose.project={args.project}"])
        if result.strip():
            raise ValueError("refusing pre-existing Compose resources")
    args.state.mkdir(mode=0o700, parents=False, exist_ok=False)
    private_path(args.state, directory=True)
    images = {}
    for service, var in (("platform-api", "API"), ("pipeline-worker", "WORKER"), ("web-console", "WEB")):
        # Resolve local built images once; tag changes cannot replace this candidate.
        value = subprocess.check_output(["docker", "image", "inspect", f"iorec/{service}:0.1", "--format", "{{.Id}}"], text=True).strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("invalid candidate image identity")
        images[f"IOREC_IMAGE_{var}"] = value
    project_token, admin_token = "iorp_" + secrets.token_hex(32), secrets.token_hex(32)
    private_text(args.state / "project.token", project_token)
    private_text(args.state / "admin.token", admin_token)
    settings = {"schema_version": 1, "project": args.project,
                "api": f"http://127.0.0.1:{args.api_port}", "web": f"http://127.0.0.1:{args.web_port}",
                "environment": {**images, "POSTGRES_PASSWORD": secrets.token_hex(32),
                    "IOREC_AUTH_MODE": "token", "IOREC_USER_TOKENS": admin_token + "=qualification:admin",
                    "IOREC_BOOTSTRAP_PROJECT_TOKEN": project_token, "IOREC_BIND_ADDR": "127.0.0.1",
                    "IOREC_HTTP_PORT": str(args.web_port), "IOREC_QUALIFY_API_PORT": str(args.api_port)}}
    atomic_json(args.state / "settings.json", settings)
    return settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "start", "status", "soak"))
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--project", default="iorec-qual-ws")
    parser.add_argument("--api-port", default=48381, type=int)
    parser.add_argument("--web-port", default=48382, type=int)
    args, extra = parser.parse_known_args()
    if args.command != "soak" and extra:
        parser.error("extra arguments only accepted for soak")
    args.state = args.state.absolute()
    if args.command == "init":
        initialize(args)
        print(json.dumps({"initialized": True, "state": str(args.state)}))
        return 0
    private_path(args.state, directory=True)
    private_path(args.state / "settings.json")
    settings = json.loads((args.state / "settings.json").read_text())
    if not re.fullmatch(r"iorec-qual-[a-z0-9-]{1,36}", settings["project"]):
        raise ValueError("invalid isolated project")
    env = environment(settings)
    compose = connected_soak.compose_base(settings["project"], COMPOSE)
    token = connected_soak.read_private_file(args.state / "admin.token", "admin token")
    if args.command == "status":
        print(json.dumps(connected_soak.api_json(settings["api"], "/v1/system/health", token)))
        return 0
    lock_fd = os.open(args.state / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "start":
            # No build/pull: candidate image IDs already resolved at initialization.
            subprocess.run([*compose, "up", "-d", "--no-build", "--pull", "never", "--wait"], env=env, check=True, timeout=180)
            connected_soak.wait_until("qualified worker health", 60,
                lambda: connected_soak.api_json(settings["api"], "/v1/system/health", token).get("ok") is True)
            print(json.dumps({"started": True, "api": settings["api"], "web": settings["web"]}))
            return 0
        # The caller controls workload parameters, never the target project/API or credentials.
        allowed = {"--iorec", "--output", "--work-dir", "--duration-seconds", "--collectors",
                   "--request-interval-seconds", "--segment-seconds", "--drain-seconds", "--node"}
        if len(extra) % 2 or any(extra[i] not in allowed for i in range(0, len(extra), 2)):
            raise ValueError("invalid soak arguments")
        command = [sys.executable, str(ROOT / "tools/connected_soak.py"),
                   "--api", settings["api"], "--project-token-file", str(args.state / "project.token"),
                   "--admin-token-file", str(args.state / "admin.token"), "--compose-project", settings["project"],
                   "--workload", "mixed-websocket"]
        for path in COMPOSE:
            command += ["--compose-file", str(path)]
        return subprocess.run(command + extra, env=env, pass_fds=(lock.fileno(),)).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # A subprocess/config exception can contain credentials. Print only its type.
        print("qualification platform failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
