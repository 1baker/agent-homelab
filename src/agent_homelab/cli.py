from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from . import __version__, tailscale_policy
from .bootstrap import bootstrap_node, create_recovery_bundle
from .deploy import apply_plan, build_plan, format_plan
from .migrations import migrate_payload
from .model import InventoryError, load_inventory, topology_for, validate_inventory
from .render import render_inventory
from .service_recipes import get_operating_model, get_recipe, load_recipes
from .verify import results_json, verify_inventory


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="agent-homelab", description="Plan, render, deploy, and verify homelab ingress")
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = root.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create a synthetic starter inventory")
    init.add_argument("path", nargs="?", default="homelab.yaml")
    init.add_argument("--topology", choices=["combined", "direct", "relay"], default="combined")
    init.add_argument("--force", action="store_true")

    validate = sub.add_parser("validate", help="validate schema and safety invariants")
    _inventory_arg(validate)

    render = sub.add_parser("render", help="render deterministic node configuration")
    _inventory_arg(render)
    render.add_argument("--output", default="rendered")

    plan = sub.add_parser("plan", help="compare rendered and installed node state")
    _inventory_arg(plan)
    plan.add_argument("--rendered", default="rendered")
    plan.add_argument("--node", required=True)

    apply = sub.add_parser("apply", help="validate, back up, atomically install, and optionally reload one node")
    _inventory_arg(apply)
    apply.add_argument("--rendered", default="rendered")
    apply.add_argument("--node", required=True)
    apply.add_argument("--dry-run", action="store_true")

    verify = sub.add_parser("verify", help="probe configured local and public routes")
    _inventory_arg(verify)
    verify.add_argument("--timeout", type=float, default=10.0)

    doctor = sub.add_parser("doctor", help="inspect local prerequisites without mutation")
    _inventory_arg(doctor, required=False)

    maintenance = sub.add_parser("maintenance", help="validate and report drift for every deployable node")
    _inventory_arg(maintenance)

    bootstrap = sub.add_parser("bootstrap", help="plan or create persistent node state without overwriting it")
    _inventory_arg(bootstrap)
    bootstrap.add_argument("--node", required=True)
    bootstrap.add_argument("--acme-email", default=os.environ.get("AGENT_HOMELAB_ACME_EMAIL"))
    bootstrap.add_argument("--apply", action="store_true")

    recovery = sub.add_parser("recovery-bundle", help="create a private non-secret recovery archive")
    _inventory_arg(recovery)
    recovery.add_argument("--rendered")
    recovery.add_argument("--output", default="recovery-agent-homelab.tar.gz")

    migrate = sub.add_parser("migrate", help="migrate an older inventory to the latest schema")
    _inventory_arg(migrate)
    migrate.add_argument("--output", required=True)

    service = sub.add_parser("service", help="manage service inventory entries")
    service_sub = service.add_subparsers(dest="service_command", required=True)
    add = service_sub.add_parser("upsert", help="create or update a service")
    _inventory_arg(add)
    add.add_argument("name")
    add.add_argument("--upstream-node", required=True)
    add.add_argument("--port", type=int, required=True)
    add.add_argument("--port-source", required=True)
    add.add_argument("--scheme", choices=["http", "https"], default="http")
    add.add_argument("--host", default="host.docker.internal")
    add.add_argument("--allow-ephemeral-port", action="store_true")
    add.add_argument("--local-hostname")
    add.add_argument("--public-hostname")
    add.add_argument("--edge-node")
    add.add_argument("--entrypoint", default="websecure")
    add.add_argument("--auth-policy", choices=["one_factor", "two_factor", "bypass", "deny"])
    remove = service_sub.add_parser("remove", help="remove a service")
    _inventory_arg(remove)
    remove.add_argument("name")

    recipe = sub.add_parser("recipe", help="inspect the installed service recipe catalog")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    recipe_sub.add_parser("list", help="list available service recipes")
    recipe_sub.add_parser("policy", help="show the recommended service operating model")
    recipe_show = recipe_sub.add_parser("show", help="show one service recipe")
    recipe_show.add_argument("name")

    tailscale_policy.add_parser(sub)

    return root


def _inventory_arg(command: argparse.ArgumentParser, *, required: bool = True) -> None:
    command.add_argument("--inventory", default="homelab.yaml" if required else None)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "tailscale-policy":
        return tailscale_policy.run(args)
    try:
        if args.command == "init":
            return _init(args)
        if args.command == "validate":
            inventory = load_inventory(args.inventory)
            print(json.dumps(_inventory_summary(inventory.data), indent=2, sort_keys=True))
            return 0
        if args.command == "render":
            inventory = load_inventory(args.inventory)
            print(json.dumps(render_inventory(inventory, args.output), indent=2, sort_keys=True))
            return 0
        if args.command == "plan":
            inventory = load_inventory(args.inventory)
            print(format_plan(build_plan(inventory, args.rendered, args.node)))
            return 0
        if args.command == "apply":
            inventory = load_inventory(args.inventory)
            plan = build_plan(inventory, args.rendered, args.node)
            print(json.dumps(apply_plan(inventory, plan, dry_run=args.dry_run), indent=2, sort_keys=True))
            return 0
        if args.command == "verify":
            results = verify_inventory(load_inventory(args.inventory), timeout=args.timeout)
            print(results_json(results))
            return 0 if all(result.ok for result in results) else 1
        if args.command == "doctor":
            return _doctor(args.inventory)
        if args.command == "maintenance":
            return _maintenance(args.inventory)
        if args.command == "bootstrap":
            result = bootstrap_node(
                load_inventory(args.inventory), args.node, acme_email=args.acme_email, apply=args.apply
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "recovery-bundle":
            result = create_recovery_bundle(load_inventory(args.inventory), args.output, args.rendered)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "migrate":
            source = Path(args.inventory).expanduser()
            raw = yaml.safe_load(source.read_text())
            if not isinstance(raw, dict):
                raise InventoryError("Inventory root must be a mapping")
            migrated, changes = migrate_payload(raw)
            target = Path(args.output).expanduser()
            _atomic_yaml_write(target, migrated)
            print(json.dumps({"status": "migrated", "output": str(target), "changes": changes}, indent=2))
            return 0
        if args.command == "service":
            return _service(args)
        if args.command == "recipe":
            recipes = load_recipes()
            if args.recipe_command == "list":
                result = sorted(recipes)
            elif args.recipe_command == "policy":
                result = get_operating_model()
            else:
                result = get_recipe(args.name)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except (InventoryError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


def _init(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser()
    if target.exists() and not args.force:
        raise InventoryError(f"Refusing to overwrite {target}; use --force")
    data = _starter_inventory(args.topology)
    validate_inventory(data)
    _atomic_yaml_write(target, data)
    print(json.dumps({"status": "created", "path": str(target), "topology": args.topology}, indent=2))
    return 0


def _starter_inventory(topology: str) -> dict[str, Any]:
    if topology == "relay":
        nodes = {
            "app-host": {
                "roles": ["service_host"],
                "connect": {"address": "192.0.2.10", "ssh_alias": "app-host"},
                "ingress": {"scheme": "http", "port": 80},
                "deploy": {
                    "mode": "ssh",
                    "root": "/opt/agent-homelab",
                    "state_root": "/var/lib/agent-homelab",
                    "validate_command": ["docker", "compose", "config", "--quiet"],
                    "reload_command": ["docker", "compose", "up", "-d"],
                },
            },
            "gateway": {
                "roles": ["edge_gateway"],
                "connect": {"address": "198.51.100.20", "ssh_alias": "gateway"},
                "deploy": {
                    "mode": "ssh",
                    "root": "/opt/agent-homelab",
                    "state_root": "/var/lib/agent-homelab",
                    "validate_command": ["docker", "compose", "config", "--quiet"],
                    "reload_command": ["docker", "compose", "up", "-d"],
                },
            },
        }
        edge = "gateway"
        upstream = "app-host"
    else:
        nodes = {
            "homelab": {
                "roles": ["service_host", "edge_gateway"],
                "connect": {"address": "192.0.2.10"},
                "ingress": {"scheme": "http", "port": 80},
                "deploy": {
                    "mode": "local",
                    "root": "/opt/agent-homelab",
                    "state_root": "/var/lib/agent-homelab",
                    "validate_command": ["docker", "compose", "config", "--quiet"],
                    "reload_command": ["docker", "compose", "up", "-d"],
                },
            }
        }
        edge = upstream = "homelab"
    return {
        "schema_version": 1,
        "site": {"domain": "example.net", "timezone": "Etc/UTC", "certificate_resolver": "letsencrypt"},
        "nodes": nodes,
        "services": {
            "hello": {
                "upstream": {
                    "node": upstream,
                    "scheme": "http",
                    "host": "host.docker.internal",
                    "port": 8080,
                    "port_source": "compose.yaml ports 8080:8080",
                },
                "local": {"enabled": True, "hostname": "hello.localhost"},
                "public": {"enabled": True, "hostname": "hello.example.net", "edge_node": edge},
            }
        },
    }


def _doctor(inventory_path: str | None) -> int:
    checks: dict[str, Any] = {
        "python": sys.version.split()[0],
        "docker": shutil.which("docker"),
        "ssh": shutil.which("ssh"),
        "scp": shutil.which("scp"),
        "ports": {"80": _port_available(80), "443": _port_available(443)},
    }
    ok = bool(checks["docker"] and checks["ssh"] and checks["scp"])
    if inventory_path:
        inventory = load_inventory(inventory_path)
        checks["inventory"] = _inventory_summary(inventory.data)
    checks["ok"] = ok
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if ok else 1


def _port_available(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def _maintenance(inventory_path: str) -> int:
    inventory = load_inventory(inventory_path)
    with tempfile.TemporaryDirectory() as temp_dir:
        render_inventory(inventory, temp_dir)
        plans = []
        for node_name, node in inventory.nodes.items():
            if node.get("deploy"):
                plans.append(build_plan(inventory, temp_dir, node_name).to_dict())
    result = {"status": "ok", "nodes": plans, "drifted_nodes": [item["node"] for item in plans if item["changed"]]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _service(args: argparse.Namespace) -> int:
    path = Path(args.inventory).expanduser()
    inventory = load_inventory(path)
    data = inventory.data
    if args.service_command == "remove":
        if args.name not in data["services"]:
            raise InventoryError(f"Unknown service: {args.name}")
        del data["services"][args.name]
    else:
        if bool(args.public_hostname) != bool(args.edge_node):
            raise InventoryError("--public-hostname and --edge-node must be supplied together")
        if args.auth_policy and not args.public_hostname:
            raise InventoryError("--auth-policy requires public ingress")
        service: dict[str, Any] = {
            "upstream": {
                "node": args.upstream_node,
                "scheme": args.scheme,
                "host": args.host,
                "port": args.port,
                "port_source": args.port_source,
            },
            "local": {"enabled": bool(args.local_hostname)},
            "public": {"enabled": bool(args.public_hostname)},
        }
        if args.allow_ephemeral_port:
            service["upstream"]["allow_ephemeral_port"] = True
        if args.local_hostname:
            service["local"]["hostname"] = args.local_hostname
        if args.public_hostname:
            service["public"].update(
                {"hostname": args.public_hostname, "edge_node": args.edge_node, "entrypoint": args.entrypoint}
            )
        if args.auth_policy:
            service["public"]["auth"] = {"provider": "authelia", "policy": args.auth_policy}
        data["services"][args.name] = service
    validate_inventory(data)
    _atomic_yaml_write(path, data)
    print(json.dumps({"status": args.service_command, "service": args.name, "inventory": str(path)}, indent=2))
    return 0


def _atomic_yaml_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(yaml.safe_dump(data, sort_keys=False))
    os.replace(temporary, path)


def _inventory_summary(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "valid",
        "schema_version": data["schema_version"],
        "nodes": sorted(data["nodes"]),
        "services": {
            name: {"topology": topology_for(service), "upstream_node": service["upstream"]["node"]}
            for name, service in sorted(data["services"].items())
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
