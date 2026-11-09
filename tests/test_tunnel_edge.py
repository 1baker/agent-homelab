from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from agent_homelab.model import InventoryError, load_inventory, validate_inventory
from agent_homelab.render import render_inventory
from agent_homelab.tunnel_edge import dynamic_config, edge_safety_problems, static_config

FIXTURES = Path(__file__).parent / "fixtures"


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


@pytest.fixture()
def rendered(tmp_path: Path) -> Path:
    render_inventory(load_inventory(FIXTURES / "tunnel.yaml"), tmp_path / "out")
    return tmp_path / "out" / "nodes" / "edge"


def test_static_entrypoints_are_loopback_published_and_trust_only_the_tunnel_hop(rendered: Path) -> None:
    static = read_yaml(rendered / "traefik/traefik.yaml")
    assert set(static["entryPoints"]) == {"auth", "dashboard", "apps"}
    for entrypoint in static["entryPoints"].values():
        assert entrypoint["forwardedHeaders"]["trustedIPs"] == ["127.0.0.1/32", "198.51.100.1/32"]
    assert static["providers"]["file"] == {"directory": "/etc/traefik/dynamic", "watch": True}
    assert "certificatesResolvers" not in static
    compose = read_yaml(rendered / "compose.yaml")["services"]["traefik"]
    assert compose["ports"] == ["127.0.0.1:9082:9082", "127.0.0.1:9080:9080", "127.0.0.1:9081:9081"]
    assert "./traefik/dynamic:/etc/traefik/dynamic:ro" in compose["volumes"]


def test_protected_routers_pin_host_before_forward_auth(rendered: Path) -> None:
    http = read_yaml(rendered / "traefik/dynamic/services.yaml")["http"]
    routers, middlewares = http["routers"], http["middlewares"]
    expected = ["edge-rate-limit", "edge-strip-identity", "authz-host-browser-example-net", "authelia-forward-auth"]
    assert routers["browser-public"]["middlewares"] == [*expected, "edge-secure-headers"]
    assert routers["browser-viewer-public"]["middlewares"] == [*expected, "browser-viewer-headers"]
    assert routers["browser-viewer-public"]["rule"] == "Host(`browser.example.net`) && PathPrefix(`/guacamole`)"
    assert routers["traefik-dashboard"]["middlewares"][2] == "authz-host-traefik-example-net"
    pin = middlewares["authz-host-browser-example-net"]["headers"]["customRequestHeaders"]
    assert pin == {
        "X-Forwarded-Host": "browser.example.net",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Uri": "",
        "X-Forwarded-Method": "",
        "X-Forwarded-Prefix": "",
        "X-Forwarded-Port": "",
    }
    assert middlewares["edge-rate-limit"]["rateLimit"]["sourceCriterion"] == {"requestHeaderName": "Cf-Connecting-IP"}
    assert middlewares["edge-strip-identity"]["headers"]["customRequestHeaders"]["Remote-User"] == ""
    assert http["services"]["browser-edge"]["loadBalancer"]["servers"] == [{"url": "http://198.51.100.1:19081"}]
    assert edge_safety_problems(read_yaml(rendered / "traefik/traefik.yaml"), {"http": http}) == []


def test_oauth_mcp_routes_skip_forward_auth_and_use_their_own_bridge(rendered: Path) -> None:
    http = read_yaml(rendered / "traefik/dynamic/services.yaml")["http"]
    for name in ("notes-oauth-metadata", "notes-oauth-mcp"):
        assert "authelia-forward-auth" not in http["routers"][name]["middlewares"]
        assert http["routers"][name]["service"] == "notes-mcp"
    assert http["routers"]["notes-oauth-mcp"]["rule"] == "Host(`notes.example.net`) && Path(`/mcp`)"
    assert http["services"]["notes-mcp"]["loadBalancer"]["servers"] == [{"url": "http://198.51.100.1:19111"}]
    assert http["routers"]["notes-public"]["middlewares"][3] == "authelia-forward-auth"


def test_tunnel_ingress_bridges_probes_and_policy_fragment(rendered: Path) -> None:
    ingress = read_yaml(rendered / "cloudflared/ingress.yml")["ingress"]
    assert ingress[-1] == {"service": "http_status:404"}
    assert {"hostname": "auth.example.net", "service": "http://127.0.0.1:9080"} in ingress
    assert {"hostname": "notes.example.net", "service": "http://127.0.0.1:9082"} in ingress
    sockets = sorted(p.name for p in (rendered / "systemd").iterdir())
    assert sockets == [
        "agent-homelab-bridge-19081.service",
        "agent-homelab-bridge-19081.socket",
        "agent-homelab-bridge-19111.service",
        "agent-homelab-bridge-19111.socket",
    ]
    socket = (rendered / "systemd/agent-homelab-bridge-19081.socket").read_text()
    assert "ListenStream=198.51.100.1:19081" in socket and "FreeBind=yes" in socket
    service = (rendered / "systemd/agent-homelab-bridge-19111.service").read_text()
    assert "ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:19110" in service
    assert "Requires=notes-oauth-relay.service" in service
    probes = {p["name"]: p for p in json.loads((rendered / "probes.json").read_text())}
    assert probes["browser-forged-forwarded-host"]["headers"] == {"X-Forwarded-Host": "auth.example.net"}
    assert probes["browser-forged-forwarded-host"]["expect"] == [302, 401]
    assert probes["notes-mcp-challenge"]["method"] == "POST" and probes["notes-mcp-challenge"]["expect"] == [401]
    rules = read_yaml(rendered / "authelia/access_control.yml")["access_control"]
    assert rules["default_policy"] == "deny"
    assert {"domain": "auth.example.net", "policy": "bypass"} in rules["rules"]
    assert not (rendered / "authelia/configuration.yml").exists()


def test_safety_check_flags_the_unpinned_forward_auth_shape() -> None:
    data = load_inventory(FIXTURES / "tunnel.yaml").data
    static = static_config(data["nodes"]["edge"])
    dynamic = dynamic_config(data, "edge")
    for router in dynamic["http"]["routers"].values():
        router["middlewares"] = [m for m in router.get("middlewares", []) if not m.startswith("authz-host-")]
    problems = edge_safety_problems(static, dynamic)
    assert any(p.startswith("browser-public:") for p in problems)
    assert any(p.startswith("traefik-dashboard:") for p in problems)
    # A pin for the wrong host does not count.
    dynamic = dynamic_config(data, "edge")
    dynamic["http"]["middlewares"]["authz-host-browser-example-net"]["headers"]["customRequestHeaders"][
        "X-Forwarded-Host"
    ] = "auth.example.net"
    assert any(p.startswith("browser-public:") for p in edge_safety_problems(static, dynamic))
    # Untrusting entrypoints (direct TLS edge) need no pin.
    for entrypoint in static["entryPoints"].values():
        del entrypoint["forwardedHeaders"]
    assert edge_safety_problems(static, dynamic) == []


def _mutated(mutate) -> dict:
    data = copy.deepcopy(load_inventory(FIXTURES / "tunnel.yaml").data)
    mutate(data)
    return data


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["nodes"]["edge"]["edge"].update(trusted_ips=["0.0.0.0/0"]), "too broad"),
        (lambda d: d["nodes"]["edge"]["edge"].pop("docker_gateway"), "docker_gateway: required"),
        (lambda d: d["nodes"]["edge"]["edge"]["entrypoints"].update(extra={"port": 9082}), "ports must be unique"),
        (lambda d: d["nodes"]["edge"]["edge"]["authelia"].update(entrypoint="nope"), "unknown entrypoint"),
        (lambda d: d["services"]["browser"]["public"].update(entrypoint="websecure"), "must name a tunnel entrypoint"),
        (lambda d: d["services"]["browser"]["upstream"].pop("bridge"), "needs a bridge socket"),
        (lambda d: d["services"]["notes"]["upstream"].update(port=19099), "already bridges a different upstream"),
    ],
)
def test_unsafe_tunnel_inventories_are_rejected(mutate, message: str) -> None:
    with pytest.raises(InventoryError, match=message):
        validate_inventory(_mutated(mutate))


def test_bridges_and_oauth_mcp_require_a_tunnel_edge() -> None:
    data = yaml.safe_load((FIXTURES / "relay.yaml").read_text())
    data["services"]["photos"]["upstream"]["bridge"] = {"port": 19081}
    data["services"]["photos"]["public"]["oauth_mcp"] = {"upstream": dict(data["services"]["photos"]["upstream"])}
    with pytest.raises(InventoryError) as error:
        validate_inventory(data)
    assert "bridges are rendered only for tunnel edges" in str(error.value)
    assert "oauth_mcp: supported only on a tunnel edge" in str(error.value)
