"""Task-scoped Docker network selection; never prune or alter other networks.

An optional explicit RFC1918 subnet avoids dependence on Docker's default pool.
The allocation probe creates/removes only its own labelled, empty bridge. It is
a point-in-time check, not a reservation or a guarantee against later races.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tomllib


class NetworkFailure(Exception):
    """Fixed diagnostics only: subprocess payloads are not public errors."""


LABEL = "io.iorec.audit.network-probe"
PRIVATE_RANGES = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validated_subnet(value):
    try:
        net = ipaddress.ip_network(value, strict=True)
        if (net.version != 4 or not 24 <= net.prefixlen <= 28
                or not any(net.subnet_of(parent) for parent in PRIVATE_RANGES)):
            raise ValueError()
    except (ValueError, TypeError):
        raise NetworkFailure("task_network_requires_canonical_RFC1918_IPv4_prefix_24_to_28") from None
    if str(net) != value:
        raise NetworkFailure("task_network_requires_canonical_RFC1918_IPv4_prefix_24_to_28")
    return net


def network_compose(value):
    return {"networks": {"default": {"ipam": {"config": [{"subnet": str(validated_subnet(value))}]}}}}


def task_network_input(task: Path, value):
    subnet = str(validated_subnet(value))
    with (task / "task.toml").open("rb") as src:
        raw = src.read((1 << 20) + 1)
    if len(raw) > 1 << 20:
        raise NetworkFailure("task_network_task_config_too_large")
    config = tomllib.loads(raw.decode())
    if config.get("environment", {}).get("allow_internet", True) is not True:
        raise NetworkFailure("task_network_requires_direct_task_network_no_egress_sidecar")
    if config.get("verifier", {}).get("environment_mode", "same") not in ("same", "shared"):
        raise NetworkFailure("task_network_requires_shared_verifier")
    if any((task / "environment" / name).exists() for name in (
            "docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml")):
        raise NetworkFailure("task_network_requires_single_service_task")
    return {"subnet": subnet, "scope": "single_task_compose_default_network_not_daemon_configuration"}


def command(args):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise NetworkFailure("task_network_command_failed_or_timed_out") from None
    if len(result.stdout) > 1 << 20 or len(result.stderr) > 1 << 20:
        raise NetworkFailure("task_network_command_output_limit")
    return result


def checked(args):
    result = command(args)
    if result.returncode:
        raise NetworkFailure("task_network_read_only_inspection_failed")
    return result.stdout


def assert_no_overlap(value):
    """Read-only; check all local IPv4 routing tables and Docker IPAM ranges."""
    target = validated_subnet(value)
    endpoint = os.environ.get("DOCKER_HOST") if not os.environ.get("DOCKER_CONTEXT") else None
    if endpoint is None:
        try:
            endpoint = json.loads(checked(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}",
                                          *([os.environ["DOCKER_CONTEXT"]] if os.environ.get("DOCKER_CONTEXT") else [])]))
        except (ValueError, TypeError):
            raise NetworkFailure("task_network_docker_endpoint_unknown") from None
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise NetworkFailure("task_network_requires_local_unix_docker_endpoint_for_route_check")
    ids = checked(["docker", "network", "ls", "--quiet", "--no-trunc"]).decode().split()
    if len(ids) > 1000 or any(not re.fullmatch(r"[0-9a-f]{64}", x) for x in ids):
        raise NetworkFailure("task_network_inventory_invalid_or_too_large")
    try:
        networks = []
        if ids:
            raw = checked(["docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", *ids])
            lines = raw.splitlines()
            if len(lines) != len(ids):
                raise ValueError()
            for line in lines:
                config = json.loads(line)
                if config is not None and not isinstance(config, list):
                    raise ValueError()
                for entry in config or []:
                    if entry.get("Subnet"):
                        networks.append(ipaddress.ip_network(entry["Subnet"], strict=False))
        routes = json.loads(checked(["ip", "-j", "-4", "route", "show", "table", "all"]))
        if not isinstance(routes, list):
            raise ValueError()
        for route in routes:
            dst = route.get("dst")
            if not dst:
                raise ValueError()
            if dst in ("default", "0.0.0.0/0"):
                continue
            networks.append(ipaddress.ip_network(dst, strict=False))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise NetworkFailure("task_network_inventory_invalid") from None
    if any(n.version == 4 and target.overlaps(n) for n in networks):
        raise NetworkFailure("task_network_overlaps_existing_network_or_host_route")
    return {"subnet": value, "docker_networks_checked": len(ids), "host_routes_checked": len(routes)}


def cleanup_probe(name, nonce):
    # Never delete by a broad filter or inferred name. Recheck exact label,
    # returned immutable ID and absence of endpoints immediately before removal.
    fmt = '{"id":{{json .Id}},"labels":{{json .Labels}},"endpoints":{{len .Containers}}}'
    result = command(["docker", "network", "inspect", "--format", fmt, name])
    if result.returncode:
        missing = (rb"network\s+" + re.escape(name.encode()) + rb"\s+not found|no such network:\s*"
                   + re.escape(name.encode()) + rb"(?:\s|$)")
        if re.search(missing, result.stderr, re.IGNORECASE):
            return
        raise NetworkFailure("task_network_probe_cleanup_unverified")
    try:
        item = json.loads(result.stdout)
        owned = (item.get("labels", {}).get(LABEL) == nonce and item.get("endpoints") == 0
                 and re.fullmatch(r"[0-9a-f]{64}", item.get("id", "")))
    except (ValueError, TypeError, AttributeError):
        owned = False
    if not owned:
        raise NetworkFailure("task_network_probe_not_owned_or_in_use_no_removal")
    if command(["docker", "network", "rm", item["id"]]).returncode:
        raise NetworkFailure("task_network_probe_cleanup_failed")


def probe_network(value):
    inventory = assert_no_overlap(value)
    nonce = secrets.token_hex(16)
    name = "iorec-network-probe-" + nonce
    try:
        result = command(["docker", "network", "create", "--driver", "bridge", "--subnet", value,
                          "--label", LABEL + "=" + nonce, name])
        if result.returncode or not re.fullmatch(rb"[0-9a-f]{64}\s*", result.stdout):
            raise NetworkFailure("task_network_allocation_probe_failed_no_model_launch")
    finally:
        cleanup_probe(name, nonce)
    return {**inventory, "allocation_probe": "created_and_removed", "reserves_subnet": False,
            "scope": "point_in_time_task_bridge_only_not_internet_or_provider_availability"}
