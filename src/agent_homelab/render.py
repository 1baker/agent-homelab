from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from . import tunnel_edge
from .model import Inventory, edge_mode, topology_for

TRAEFIK_IMAGE = "traefik:v3.7.8"


class RenderError(ValueError):
    """Raised when rendered configuration would violate an edge safety invariant."""


AUTHELIA_IMAGE = "authelia/authelia:4.39.20"


def render_inventory(inventory: Inventory, output_dir: str | Path) -> dict[str, Any]:
    target = Path(output_dir).expanduser().resolve()
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)

    rendered_nodes: dict[str, dict[str, Any]] = {}
    for node_name, node in inventory.nodes.items():
        node_dir = target / "nodes" / node_name
        if edge_mode(node) == "tunnel":
            _render_tunnel_node(inventory.data, node_name, node_dir)
            rendered_nodes[node_name] = {
                "roles": node["roles"],
                "services": sorted(_services_for_node(inventory.data, node_name)),
                "digest": tree_digest(node_dir),
            }
            continue
        dynamic = _dynamic_for_node(inventory.data, node_name)
        static = _static_traefik(node)
        _check_safety(node_name, static, dynamic)
        _write_yaml(node_dir / "traefik" / "dynamic" / "services.yaml", dynamic)
        _write_yaml(node_dir / "traefik" / "traefik.yaml", static)
        _write_yaml(node_dir / "compose.yaml", _compose_for_node(inventory.data, node_name))

        auth_rules = _authelia_rules(inventory.data, node_name)
        if auth_rules:
            _write_yaml(node_dir / "authelia" / "configuration.yml", _authelia_config(inventory.data, auth_rules))
            _write_text(node_dir / "state.env.example", _edge_env_example())

        rendered_nodes[node_name] = {
            "roles": node["roles"],
            "services": sorted(_services_for_node(inventory.data, node_name)),
            "digest": tree_digest(node_dir),
        }

    manifest = {
        "schema_version": 1,
        "source": inventory.path.name,
        "nodes": rendered_nodes,
    }
    _write_text(target / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _check_safety(node_name: str, static: dict[str, Any], dynamic: dict[str, Any]) -> None:
    problems = tunnel_edge.edge_safety_problems(static, dynamic)
    if problems:
        raise RenderError(f"Unsafe edge configuration for node {node_name}:\n- " + "\n- ".join(problems))


def _render_tunnel_node(data: dict[str, Any], node_name: str, node_dir: Path) -> None:
    node = data["nodes"][node_name]
    static = tunnel_edge.static_config(node)
    dynamic = tunnel_edge.dynamic_config(data, node_name)
    _check_safety(node_name, static, dynamic)
    _write_yaml(node_dir / "traefik" / "traefik.yaml", static)
    _write_yaml(node_dir / "traefik" / "dynamic" / "services.yaml", dynamic)
    compose: dict[str, Any] = {"services": {"traefik": tunnel_edge.compose_service(node, TRAEFIK_IMAGE)}}
    _write_yaml(node_dir / "compose.yaml", compose)
    _write_yaml(node_dir / "cloudflared" / "ingress.yml", tunnel_edge.cloudflared_ingress(data, node_name))
    for unit_name, text in sorted(tunnel_edge.bridge_units(data, node_name).items()):
        _write_text(node_dir / "systemd" / unit_name, text)
    _write_text(node_dir / "probes.json", json.dumps(tunnel_edge.route_probes(data, node_name), indent=2) + "\n")
    rules = tunnel_edge.authelia_access_rules(data, node_name)
    if rules:
        # Authelia itself (OIDC clients, MFA, secrets) stays operator-managed; this is the reviewed policy fragment.
        _write_yaml(
            node_dir / "authelia" / "access_control.yml", {"access_control": {"default_policy": "deny", "rules": rules}}
        )


def _services_for_node(data: dict[str, Any], node_name: str) -> set[str]:
    result: set[str] = set()
    for name, service in data["services"].items():
        if service["upstream"]["node"] == node_name:
            result.add(name)
        if service.get("public", {}).get("enabled") and service["public"]["edge_node"] == node_name:
            result.add(name)
    return result


def _dynamic_for_node(data: dict[str, Any], node_name: str) -> dict[str, Any]:
    routers: dict[str, Any] = {
        "agent-homelab-health": {
            "rule": "Path(`/.well-known/agent-homelab/health`)",
            "entryPoints": ["web"],
            "service": "ping@internal",
            "priority": 1000,
        }
    }
    services: dict[str, Any] = {}
    middlewares: dict[str, Any] = {}

    for name, service in sorted(data["services"].items()):
        upstream_node = service["upstream"]["node"]
        local = service.get("local", {})
        public = service.get("public", {})

        if upstream_node == node_name:
            for middleware_name, definition in sorted(service.get("forward_auth", {}).items()):
                middlewares[middleware_name] = {
                    "forwardAuth": {
                        "address": definition["address"],
                        "trustForwardHeader": definition.get("trust_forward_header", True),
                        "maxResponseBodySize": 1048576,
                        "authResponseHeaders": definition.get("auth_response_headers", []),
                    }
                }
            services[f"{name}-upstream"] = _load_balancer(service["upstream"])
            if local.get("enabled"):
                routers[f"{name}-local"] = {
                    "rule": f"Host(`{local['hostname']}`)",
                    "entryPoints": ["web"],
                    "service": f"{name}-upstream",
                }
            if public.get("enabled"):
                routers[f"{name}-origin"] = {
                    "rule": f"Host(`{public['hostname']}`)",
                    "entryPoints": ["web"],
                    "service": f"{name}-upstream",
                }
            _add_path_routes(routers, services, name, service, node_name)

        if public.get("enabled") and public["edge_node"] == node_name:
            edge_service_name = f"{name}-edge"
            if topology_for(service) == "direct":
                services[edge_service_name] = _load_balancer(service["upstream"])
            else:
                origin = data["nodes"][upstream_node]
                ingress = origin.get("ingress", {})
                scheme = ingress.get("scheme", "http")
                port = ingress.get("port", 80)
                address = origin["connect"]["address"]
                services[edge_service_name] = {
                    "loadBalancer": {"passHostHeader": True, "servers": [{"url": f"{scheme}://{address}:{port}"}]}
                }
            router: dict[str, Any] = {
                "rule": f"Host(`{public['hostname']}`)",
                "entryPoints": [public.get("entrypoint", "websecure")],
                "service": edge_service_name,
                "tls": {"certResolver": data["site"].get("certificate_resolver", "letsencrypt")},
            }
            if public.get("auth", {}).get("provider") == "authelia":
                middleware_name = "authelia-forward-auth"
                router["middlewares"] = [middleware_name]
                middlewares[middleware_name] = {
                    "forwardAuth": {
                        "address": data["site"]
                        .get("authelia", {})
                        .get("url", "http://authelia:9091/api/authz/forward-auth"),
                        "trustForwardHeader": True,
                        "maxResponseBodySize": 1048576,
                        "authResponseHeaders": ["Remote-User", "Remote-Groups", "Remote-Name", "Remote-Email"],
                    }
                }
            routers[f"{name}-public"] = router

    if _authelia_rules(data, node_name):
        domain = data["site"]["domain"]
        routers["authelia"] = {
            "rule": f"Host(`auth.{domain}`)",
            "entryPoints": ["websecure"],
            "service": "authelia",
            "tls": {"certResolver": data["site"].get("certificate_resolver", "letsencrypt")},
        }
        services["authelia"] = {"loadBalancer": {"servers": [{"url": "http://authelia:9091"}]}}

    http: dict[str, Any] = {"routers": routers, "services": services}
    if middlewares:
        http["middlewares"] = middlewares
    return {"http": http}


def _add_path_routes(
    routers: dict[str, Any], services: dict[str, Any], name: str, service: dict[str, Any], node_name: str
) -> None:
    hosts: list[tuple[str, str]] = []
    if service.get("local", {}).get("enabled"):
        hosts.append(("local", service["local"]["hostname"]))
    if service.get("public", {}).get("enabled"):
        hosts.append(("origin", service["public"]["hostname"]))
    for index, route in enumerate(service.get("path_routes", [])):
        if route["upstream"]["node"] != node_name:
            continue
        service_key = f"{name}-{route['name']}-upstream"
        services[service_key] = _load_balancer(route["upstream"])
        for host_kind, hostname in hosts:
            router: dict[str, Any] = {
                "rule": f"Host(`{hostname}`) && PathPrefix(`{route['path_prefix']}`)",
                "entryPoints": ["web"],
                "service": service_key,
                "priority": 100 + index,
            }
            if route.get("middlewares"):
                router["middlewares"] = route["middlewares"]
            routers[f"{name}-{route['name']}-{host_kind}"] = router


def _load_balancer(upstream: dict[str, Any]) -> dict[str, Any]:
    return {
        "loadBalancer": {
            "passHostHeader": True,
            "servers": [{"url": f"{upstream['scheme']}://{upstream['host']}:{upstream['port']}"}],
        }
    }


def _static_traefik(node: dict[str, Any]) -> dict[str, Any]:
    entrypoints: dict[str, Any] = {"web": {"address": ":80"}}
    if "edge_gateway" in node["roles"]:
        entrypoints["websecure"] = {"address": ":443"}
    config: dict[str, Any] = {
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        "api": {"dashboard": False},
        "entryPoints": entrypoints,
        "providers": {"file": {"directory": "/etc/traefik/dynamic", "watch": True}},
        "ping": {},
        "log": {"level": "INFO"},
    }
    if "edge_gateway" in node["roles"]:
        config["certificatesResolvers"] = {
            "letsencrypt": {
                "acme": {
                    "storage": "/letsencrypt/acme.json",
                    "httpChallenge": {"entryPoint": "web"},
                }
            }
        }
    return config


def _compose_for_node(data: dict[str, Any], node_name: str) -> dict[str, Any]:
    node = data["nodes"][node_name]
    state_root = node.get("deploy", {}).get("state_root", "/var/lib/agent-homelab")
    ports = ["80:80"]
    if "edge_gateway" in node["roles"]:
        ports.append("443:443")
    traefik: dict[str, Any] = {
        "image": TRAEFIK_IMAGE,
        "restart": "unless-stopped",
        "ports": ports,
        "volumes": [
            "./traefik/traefik.yaml:/etc/traefik/traefik.yaml:ro",
            "./traefik/dynamic:/etc/traefik/dynamic:ro",
        ],
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "healthcheck": {"test": ["CMD", "traefik", "healthcheck", "--ping"], "interval": "30s", "timeout": "5s"},
    }
    if "edge_gateway" in node["roles"]:
        traefik["volumes"].append(f"{state_root}/letsencrypt:/letsencrypt")
        traefik["env_file"] = [{"path": f"{state_root}/env", "required": False}]
    services: dict[str, Any] = {"traefik": traefik}

    if _authelia_rules(data, node_name):
        services["authelia"] = {
            "image": AUTHELIA_IMAGE,
            "restart": "unless-stopped",
            "volumes": [
                "./authelia/configuration.yml:/config/configuration.yml:ro",
                f"{state_root}/authelia/users_database.yml:/config/users_database.yml:ro",
                f"{state_root}/authelia:/var/lib/authelia",
            ],
            "environment": [
                "AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/run/secrets/authelia_jwt_secret",
                "AUTHELIA_SESSION_SECRET_FILE=/run/secrets/authelia_session_secret",
                "AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/run/secrets/authelia_storage_key",
            ],
            "secrets": ["authelia_jwt_secret", "authelia_session_secret", "authelia_storage_key"],
        }

    compose: dict[str, Any] = {"services": services}
    if _authelia_rules(data, node_name):
        compose["secrets"] = {
            "authelia_jwt_secret": {"file": f"{state_root}/secrets/authelia-jwt-secret"},
            "authelia_session_secret": {"file": f"{state_root}/secrets/authelia-session-secret"},
            "authelia_storage_key": {"file": f"{state_root}/secrets/authelia-storage-key"},
        }
    return compose


def _authelia_rules(data: dict[str, Any], node_name: str) -> list[dict[str, str]]:
    rules = []
    for service in data["services"].values():
        public = service.get("public", {})
        auth = public.get("auth", {})
        if public.get("enabled") and public.get("edge_node") == node_name and auth.get("provider") == "authelia":
            rules.append({"domain": public["hostname"], "policy": auth["policy"]})
    return sorted(rules, key=lambda rule: rule["domain"])


def _authelia_config(data: dict[str, Any], rules: list[dict[str, str]]) -> dict[str, Any]:
    domain = data["site"]["domain"]
    return {
        "server": {"address": "tcp://0.0.0.0:9091/"},
        "log": {"level": "info"},
        "totp": {"issuer": domain},
        "identity_validation": {"reset_password": {}},
        "authentication_backend": {"file": {"path": "/config/users_database.yml"}},
        "access_control": {"default_policy": "deny", "rules": rules},
        "session": {
            "cookies": [
                {
                    "domain": domain,
                    "authelia_url": f"https://auth.{domain}",
                    "default_redirection_url": f"https://{domain}",
                }
            ],
        },
        "storage": {
            "local": {"path": "/var/lib/authelia/db.sqlite3"},
        },
        "notifier": {"filesystem": {"filename": "/var/lib/authelia/notification.txt"}},
    }


def _edge_env_example() -> str:
    return "TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_EMAIL=operator@example.invalid\n"


def tree_digest(path: str | Path) -> str:
    root = Path(path)
    digest = hashlib.sha256()
    for file_path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(file_path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _write_yaml(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False, default_flow_style=False))


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
