#!/usr/bin/env python3
"""Start/check the loopback-only development platform at a stable address.

This is explicitly a local dev deployment, not production authentication or
durability configuration. Existing database credentials are reused, never
rotated. Docker inspection output and generated secrets are never printed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

from harbor_audit_workflow import Failure, api_request, atomic_json, private_path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "iorec-local"
WEB = "http://127.0.0.1:8088"
API = "http://127.0.0.1:18080"


def inspect_container(name):
    result = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=15)
    if result.returncode:
        # Distinguish an unavailable daemon from a genuinely missing container.
        subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15, check=True)
        return None
    rows = json.loads(result.stdout)
    item = rows[0]
    if item.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != PROJECT:
        raise Failure("container_name_owned_by_another_project")
    return item


def container_env(item):
    return dict(entry.split("=", 1) for entry in item["Config"]["Env"] if "=" in entry) if item else {}


def status():
    result = {"profile": "local_development_loopback_only", "web_url": WEB, "api_url": API,
              "forwarding_note": "Browser/SSH forwarded ports are temporary; these are the actual host listeners."}
    for name, origin, endpoint in [("api", API, "/healthz"), ("web", WEB, "/healthz"), ("workers", API, "/v1/system/health")]:
        try:
            response = api_request(origin, endpoint)
            result[name] = {"ok": response.get("ok") is True}
            if name == "workers":
                result[name].update(scope=response.get("scope"), pools=response.get("worker_pools"), queue=response.get("queue"))
        except Exception as error:
            result[name] = {"ok": False, "error": str(error) if isinstance(error, Failure) else type(error).__name__}
    result["ok"] = all(result[key]["ok"] for key in ("api", "web", "workers"))
    return result


def start(state_dir: Path, build=False):
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_path(state_dir, directory=True)
    settings = state_dir / "local-dev-secrets.json"
    saved = {}
    if settings.exists():
        private_path(settings)
        saved = json.loads(settings.read_text())
    pg, api = inspect_container(PROJECT+"-postgres-1"), inspect_container(PROJECT+"-platform-api-1")
    pg_env, api_env = container_env(pg), container_env(api)
    if api and api_env.get("IOREC_AUTH_MODE") != "dev":
        raise Failure("refusing_to_downgrade_existing_authenticated_platform")
    # Do not reconstruct credentials for an orphaned data volume by guessing a
    # new password: neither erase the volume nor overwrite its configuration.
    volume = subprocess.run(["docker", "volume", "inspect", PROJECT+"_pgdata"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=15)
    if not pg and volume.returncode == 0 and not saved.get("POSTGRES_PASSWORD"):
        raise Failure("existing_database_volume_requires_original_private_settings")
    password = pg_env.get("POSTGRES_PASSWORD") or saved.get("POSTGRES_PASSWORD") or secrets.token_hex(32)
    if api and (api_env.get("DATABASE_URL") != f"postgres://iorec:{password}@postgres:5432/iorec"
                or api_env.get("OBJECT_STORE_ENDPOINT") or api_env.get("OBJECT_STORE_DIR") != "/data/objects"):
        raise Failure("custom_storage_configuration_requires_manual_compose")
    credentials = {"POSTGRES_PASSWORD": password,
                   "IOREC_BOOTSTRAP_PROJECT_TOKEN": api_env.get("IOREC_BOOTSTRAP_PROJECT_TOKEN") or saved.get("IOREC_BOOTSTRAP_PROJECT_TOKEN") or "iorp_"+secrets.token_hex(24),
                   "IOREC_USER_TOKENS": api_env.get("IOREC_USER_TOKENS", saved.get("IOREC_USER_TOKENS", ""))}
    atomic_json(settings, credentials)
    # Ignore unrelated deployment overrides inherited from a shell. Retain
    # Docker connection settings, PATH and credentials needed for image pulls.
    env = {k: v for k, v in os.environ.items() if not (k.startswith("IOREC_") or k.startswith("OBJECT_STORE_") or k in ("DATABASE_URL", "POSTGRES_PASSWORD"))}
    env.update(credentials, IOREC_AUTH_MODE="dev", IOREC_POSTGRES_PORT="55432", IOREC_HTTP_PORT="8088", IOREC_BIND_ADDR="127.0.0.1")
    command = ["docker", "compose", "--env-file", "/dev/null", "-p", PROJECT,
               "-f", "compose.yaml", "-f", "compose.dev.yaml", "up", "-d", "--scale", "pipeline-worker=2"]
    if build:
        command.append("--build")
    else:
        command.append("--no-recreate")
    subprocess.run(command, cwd=ROOT / "iorec-platform/deploy", env=env, check=True)
    deadline = time.monotonic()+60
    while True:
        result = status()
        if result["ok"] or time.monotonic() >= deadline:
            return result
        time.sleep(2)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "status"))
    parser.add_argument("--build", action="store_true", help="build current worktree images before starting")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/iorec-platform")
    args = parser.parse_args()
    try:
        result = start(args.state_dir, args.build) if args.command == "start" else status()
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error) if isinstance(error, Failure) else type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
