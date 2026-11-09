"""Run the rendered tunnel edge in real Traefik against a fake Authelia and app.

Opt-in: AGENT_HOMELAB_DOCKER_TESTS=1 (needs Docker and pulls traefik and python images).
The negative control proves the probe would catch the forged-forwarded-host bypass.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import yaml

from agent_homelab.model import load_inventory
from agent_homelab.render import TRAEFIK_IMAGE, render_inventory

FIXTURES = Path(__file__).parents[1] / "fixtures"
PYTHON_IMAGE = "python:3.12-alpine"
FAKE = r"""
import http.server, sys
ROLE = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if ROLE == "auth" and not self.path.startswith("/api/authz"):
            self.send_response(200); self.end_headers(); return
        if ROLE == "auth":
            host = self.headers.get("X-Forwarded-Host", "")
            if host == "auth.example.net":
                self.send_response(200); self.end_headers(); return
            if "authelia_session=good" in (self.headers.get("Cookie") or ""):
                self.send_response(200); self.send_header("Remote-User", "alice"); self.end_headers(); return
            self.send_response(302); self.send_header("Location", "https://auth.example.net/")
            self.end_headers(); return
        if self.command == "POST" and self.path == "/mcp" and not self.headers.get("Authorization"):
            self.send_response(401); self.send_header("WWW-Authenticate", 'Bearer resource_metadata="x"')
            self.end_headers(); return
        body = f"APP user={self.headers.get('Remote-User')} xfh={self.headers.get('X-Forwarded-Host')}".encode()
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 9091 if ROLE == "auth" else 8000), H).serve_forever()
"""

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_HOMELAB_DOCKER_TESTS") != "1" or not shutil.which("docker"),
    reason="set AGENT_HOMELAB_DOCKER_TESTS=1 to run Docker integration tests",
)


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def _get(port: int, host: str, path: str = "/", method: str = "GET", headers: dict[str, str] | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(
        method, path, body=b"{}" if method == "POST" else None, headers={"Host": host, **(headers or {})}
    )
    response = connection.getresponse()
    return response.status, response.read().decode()


def _start_edge(tmp_path: Path, unpinned: str = "") -> tuple[list[str], dict[str, int]]:
    """Run the rendered edge; ``unpinned`` removes host pins from "all" routers or only "path" routers."""
    tag = uuid.uuid4().hex[:8]
    network, auth, app, traefik = (f"ahtest-{tag}-{n}" for n in ("net", "auth", "app", "traefik"))
    data = yaml.safe_load((FIXTURES / "tunnel.yaml").read_text())
    edge = data["nodes"]["edge"]["edge"]
    subnet_octet = int(tag[:2], 16) % 200 + 20
    gateway = f"172.30.{subnet_octet}.1"
    edge["trusted_ips"] = ["127.0.0.1/32", f"{gateway}/32"]
    edge["authelia"]["address"] = f"http://{auth}:9091/api/authz/forward-auth"
    tmp_path.mkdir(parents=True, exist_ok=True)
    inventory_path = tmp_path / "inventory.yaml"
    inventory_path.write_text(yaml.safe_dump(data))
    render_inventory(load_inventory(inventory_path), tmp_path / "out")
    traefik_dir = tmp_path / "out/nodes/edge/traefik"
    dynamic_path = traefik_dir / "dynamic/services.yaml"
    dynamic = yaml.safe_load(dynamic_path.read_text())
    for name, service in dynamic["http"]["services"].items():
        url = f"http://{auth}:9091" if name == "authelia" else f"http://{app}:8000"
        service["loadBalancer"]["servers"] = [{"url": url}]
    if unpinned:
        for router in dynamic["http"]["routers"].values():
            if unpinned == "path" and "PathPrefix" not in router.get("rule", ""):
                continue
            router["middlewares"] = [m for m in router.get("middlewares", []) if not m.startswith("authz-host-")]
    dynamic_path.write_text(yaml.safe_dump(dynamic, sort_keys=False))
    fake = tmp_path / "fake.py"
    fake.write_text(FAKE)
    _docker("network", "create", "--subnet", f"172.30.{subnet_octet}.0/24", "--gateway", gateway, network)
    names = [traefik, app, auth]
    _docker(
        "run",
        "-d",
        "--name",
        auth,
        "--network",
        network,
        "-v",
        f"{fake}:/fake.py:ro",
        PYTHON_IMAGE,
        "python",
        "/fake.py",
        "auth",
    )
    _docker(
        "run",
        "-d",
        "--name",
        app,
        "--network",
        network,
        "-v",
        f"{fake}:/fake.py:ro",
        PYTHON_IMAGE,
        "python",
        "/fake.py",
        "app",
    )
    _docker(
        "run",
        "-d",
        "--name",
        traefik,
        "--network",
        network,
        "-p",
        "127.0.0.1::9080",
        "-p",
        "127.0.0.1::9081",
        "-p",
        "127.0.0.1::9082",
        "-v",
        f"{traefik_dir / 'traefik.yaml'}:/etc/traefik/traefik.yaml:ro",
        "-v",
        f"{traefik_dir / 'dynamic'}:/etc/traefik/dynamic:ro",
        TRAEFIK_IMAGE,
    )
    ports = {
        name: int(_docker("port", traefik, f"{port}/tcp").splitlines()[0].rsplit(":", 1)[1])
        for name, port in (("auth", 9080), ("dashboard", 9081), ("apps", 9082))
    }
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if (
                _get(ports["apps"], "x", "/.well-known/agent-homelab/health")[0] == 200
                and _get(ports["apps"], "notes.example.net", "/mcp", "POST")[0] == 401
            ):
                break
        except OSError:
            pass
        time.sleep(0.5)
    return [*names, network], ports


def _stop(names: list[str]) -> None:
    subprocess.run(["docker", "rm", "-f", *names[:-1]], capture_output=True)
    subprocess.run(["docker", "network", "rm", names[-1]], capture_output=True)


def test_rendered_tunnel_edge_blocks_forged_forwarded_host(tmp_path: Path) -> None:
    names, ports = _start_edge(tmp_path)
    try:
        forged = {"X-Forwarded-Host": "auth.example.net"}
        assert _get(ports["apps"], "browser.example.net")[0] == 302
        assert _get(ports["apps"], "browser.example.net", headers=forged)[0] == 302
        assert _get(ports["apps"], "browser.example.net", "/guacamole/", headers=forged)[0] == 302
        assert _get(ports["dashboard"], "traefik.example.net", "/api/version", headers=forged)[0] == 302
        assert _get(ports["apps"], "notes.example.net", headers={"Remote-User": "alice"})[0] == 302
        status, body = _get(
            ports["apps"], "notes.example.net", headers={"Cookie": "authelia_session=good", "Remote-User": "mallory"}
        )
        assert (status, body) == (200, "APP user=alice xfh=notes.example.net")
        assert _get(ports["auth"], "auth.example.net")[0] == 200
        assert _get(ports["apps"], "notes.example.net", "/.well-known/oauth-protected-resource/mcp")[0] == 200
        assert _get(ports["apps"], "notes.example.net", "/mcp", "POST")[0] == 401
        assert _get(ports["apps"], "other.example.net")[0] == 404
    finally:
        _stop(names)


def test_negative_control_without_host_pinning_is_bypassable(tmp_path: Path) -> None:
    names, ports = _start_edge(tmp_path, unpinned="all")
    try:
        forged = {"X-Forwarded-Host": "auth.example.net"}
        assert _get(ports["apps"], "browser.example.net")[0] == 302
        assert _get(ports["apps"], "browser.example.net", headers=forged)[0] == 200
        assert _get(ports["dashboard"], "traefik.example.net", "/api/version", headers=forged)[0] == 200
    finally:
        _stop(names)


def _run_probes(tmp_path: Path, ports: dict[str, int]) -> dict[str, bool]:
    """Run the rendered probes.json against the local Traefik, by entrypoint, using each URL's host."""
    from urllib.parse import urlsplit

    results: dict[str, bool] = {}
    for probe in json.loads((tmp_path / "out/nodes/edge/probes.json").read_text()):
        url = urlsplit(probe["url"])
        connection = http.client.HTTPConnection("127.0.0.1", ports[probe["entrypoint"]], timeout=5)
        body = probe.get("body")
        connection.request(
            probe["method"],
            url.path or "/",
            body=body.encode() if body else None,
            headers={"Host": url.hostname, **probe.get("headers", {})},
        )
        status = connection.getresponse().status
        results[probe["name"]] = status in probe["expect"]
    return results


def test_rendered_probes_pass_and_catch_a_path_only_missing_pin(tmp_path: Path) -> None:
    names, ports = _start_edge(tmp_path / "pinned")
    try:
        results = _run_probes(tmp_path / "pinned", ports)
        assert results and all(results.values()), [n for n, ok in results.items() if not ok]
        assert "browser-guacamole-forged-forwarded-host" in results
        assert "browser-edge-tailnet-example-guacamole-forged-forwarded-host" in results
    finally:
        _stop(names)
    names, ports = _start_edge(tmp_path / "path-unpinned", unpinned="path")
    try:
        failed = {n for n, ok in _run_probes(tmp_path / "path-unpinned", ports).items() if not ok}
        # Only the path-route bypass probes fail; root probes still pass, as in the reviewer's control.
        assert failed == {
            "browser-guacamole-forged-forwarded-host",
            "browser-edge-tailnet-example-guacamole-forged-forwarded-host",
        }
    finally:
        _stop(names)
