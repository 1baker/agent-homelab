"""Render a Cloudflare-Tunnel edge: cloudflared -> loopback Traefik -> bridges -> host services.

Traefik on a tunnel edge must trust X-Forwarded-* from the cloudflared/Docker hop,
and that hop forwards whatever the client sent. Every Authelia-protected router
therefore pins the forwarded host and scheme before forward-auth (see
``edge_safety_problems``); otherwise a forged X-Forwarded-Host can make Authelia
evaluate a bypass domain for a protected route.
"""

from __future__ import annotations

import re
from typing import Any

AUTHELIA_FORWARD_AUTH = "http://authelia:9091/api/authz/forward-auth"
AUTH_RESPONSE_HEADERS = ["Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"]
IDENTITY_HEADERS = [
    "Remote-User",
    "Remote-Groups",
    "Remote-Email",
    "Remote-Name",
    "X-Forwarded-User",
    "X-Forwarded-Email",
    "X-Auth-Request-User",
    "X-Auth-Request-Email",
]
CLEARED_FORWARDED = ["X-Forwarded-Uri", "X-Forwarded-Method", "X-Forwarded-Prefix", "X-Forwarded-Port"]
SECURE_HEADERS = {
    "contentTypeNosniff": True,
    "frameDeny": True,
    "referrerPolicy": "same-origin",
    "stsIncludeSubdomains": True,
    "stsSeconds": 31536000,
}
OAUTH_METADATA_PATHS = ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def host_pin_name(hostname: str) -> str:
    return f"authz-host-{slug(hostname)}"


def static_config(node: dict[str, Any]) -> dict[str, Any]:
    edge = node["edge"]
    entrypoints = {
        name: {"address": f":{value['port']}", "forwardedHeaders": {"trustedIPs": list(edge["trusted_ips"])}}
        for name, value in sorted(edge["entrypoints"].items())
    }
    return {
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        "api": {"dashboard": bool(edge.get("dashboard"))},
        "entryPoints": entrypoints,
        "providers": {"file": {"directory": "/etc/traefik/dynamic", "watch": True}},
        "ping": {},
        "log": {"level": "INFO"},
        "accessLog": {"format": "json"},
    }


def compose_service(node: dict[str, Any], image: str) -> dict[str, Any]:
    edge = node["edge"]
    return {
        "image": image,
        "restart": "unless-stopped",
        # Loopback only: cloudflared on the host is the sole client.
        "ports": [f"127.0.0.1:{v['port']}:{v['port']}" for _, v in sorted(edge["entrypoints"].items())],
        # A directory mount lets file edits reload without a container restart.
        "volumes": [
            "./traefik/traefik.yaml:/etc/traefik/traefik.yaml:ro",
            "./traefik/dynamic:/etc/traefik/dynamic:ro",
        ],
        "healthcheck": {"test": ["CMD", "traefik", "healthcheck", "--ping"], "interval": "30s", "timeout": "5s"},
    }


def _upstream_url(upstream: dict[str, Any], edge: dict[str, Any]) -> str:
    bridge = upstream.get("bridge")
    if bridge:
        return f"http://{edge['docker_gateway']}:{bridge['port']}"
    return f"{upstream['scheme']}://{upstream['host']}:{upstream['port']}"


def _load_balancer(url: str) -> dict[str, Any]:
    return {"loadBalancer": {"passHostHeader": True, "servers": [{"url": url}]}}


def dynamic_config(data: dict[str, Any], node_name: str) -> dict[str, Any]:
    node = data["nodes"][node_name]
    edge = node["edge"]
    rate = edge.get("rate_limit", {"average": 20, "burst": 40})
    middlewares: dict[str, Any] = {
        "edge-rate-limit": {
            "rateLimit": {
                **rate,
                "sourceCriterion": {"requestHeaderName": edge.get("client_ip_header", "Cf-Connecting-IP")},
            }
        },
        "edge-strip-identity": {"headers": {"customRequestHeaders": {name: "" for name in IDENTITY_HEADERS}}},
        "edge-secure-headers": {"headers": dict(SECURE_HEADERS)},
        "authelia-forward-auth": {
            "forwardAuth": {
                "address": edge.get("authelia", {}).get("address", AUTHELIA_FORWARD_AUTH),
                "trustForwardHeader": True,
                "maxResponseBodySize": 8192,
                "authResponseHeaders": list(AUTH_RESPONSE_HEADERS),
            }
        },
    }
    routers: dict[str, Any] = {
        "agent-homelab-health": {
            "rule": "Path(`/.well-known/agent-homelab/health`)",
            "entryPoints": sorted(edge["entrypoints"]),
            "service": "ping@internal",
            "priority": 1000,
        }
    }
    services: dict[str, Any] = {}

    def protected_chain(hostname: str, headers_name: str) -> list[str]:
        pin = host_pin_name(hostname)
        middlewares[pin] = {
            "headers": {
                "customRequestHeaders": {
                    "X-Forwarded-Host": hostname,
                    "X-Forwarded-Proto": "https",
                    **{name: "" for name in CLEARED_FORWARDED},
                }
            }
        }
        return ["edge-rate-limit", "edge-strip-identity", pin, "authelia-forward-auth", headers_name]

    authelia = edge.get("authelia")
    if authelia:
        services["authelia"] = _load_balancer("http://authelia:9091")
        routers["authelia"] = {
            "rule": f"Host(`{authelia['hostname']}`)",
            "entryPoints": [authelia["entrypoint"]],
            "service": "authelia",
            "middlewares": ["edge-rate-limit", "edge-secure-headers"],
        }
    dashboard = edge.get("dashboard")
    if dashboard:
        routers["traefik-dashboard"] = {
            "rule": f"Host(`{dashboard['hostname']}`)",
            "entryPoints": [dashboard["entrypoint"]],
            "service": "api@internal",
            "middlewares": protected_chain(dashboard["hostname"], "edge-secure-headers"),
        }

    for name, service in sorted(data["services"].items()):
        public = service.get("public", {})
        if not public.get("enabled") or public.get("edge_node") != node_name:
            continue
        hostname = public["hostname"]
        entrypoint = public["entrypoint"]
        policy = public.get("auth", {}).get("policy")
        protected = public.get("auth", {}).get("provider") == "authelia" and policy != "bypass"

        def headers_middleware(key: str, options: dict[str, Any] | None) -> str:
            if not options:
                return "edge-secure-headers"
            middlewares[key] = {"headers": options}
            return key

        services[f"{name}-edge"] = _load_balancer(_upstream_url(service["upstream"], edge))
        headers_name = headers_middleware(f"{name}-headers", public.get("headers"))
        chain = (
            protected_chain(hostname, headers_name)
            if protected
            else ["edge-rate-limit", "edge-strip-identity", headers_name]
        )
        routers[f"{name}-public"] = {
            "rule": f"Host(`{hostname}`)",
            "entryPoints": [entrypoint],
            "service": f"{name}-edge",
            "middlewares": chain,
        }
        for index, route in enumerate(service.get("path_routes", [])):
            key = f"{name}-{route['name']}"
            services[f"{key}-edge"] = _load_balancer(_upstream_url(route["upstream"], edge))
            route_headers = headers_middleware(f"{key}-headers", route.get("headers"))
            base = (
                protected_chain(hostname, route_headers)
                if protected
                else ["edge-rate-limit", "edge-strip-identity", route_headers]
            )
            routers[f"{key}-public"] = {
                "rule": f"Host(`{hostname}`) && PathPrefix(`{route['path_prefix']}`)",
                "entryPoints": [entrypoint],
                "service": f"{key}-edge",
                "priority": 100 + index,
                "middlewares": base + list(route.get("middlewares", [])),
            }
        for auth_name, definition in sorted(service.get("forward_auth", {}).items()):
            middlewares[auth_name] = {
                "forwardAuth": {
                    "address": definition["address"],
                    "trustForwardHeader": definition.get("trust_forward_header", True),
                    "maxResponseBodySize": 1048576,
                    "authResponseHeaders": definition.get("auth_response_headers", []),
                }
            }
        mcp = public.get("oauth_mcp")
        if mcp:
            services[f"{name}-mcp"] = _load_balancer(_upstream_url(mcp["upstream"], edge))
            metadata = " || ".join(f"Path(`{path}`)" for path in OAUTH_METADATA_PATHS)
            routers[f"{name}-oauth-metadata"] = {
                "rule": f"Host(`{hostname}`) && ({metadata})",
                "entryPoints": [entrypoint],
                "service": f"{name}-mcp",
                "middlewares": ["edge-rate-limit", "edge-strip-identity", "edge-secure-headers"],
            }
            routers[f"{name}-oauth-mcp"] = {
                "rule": f"Host(`{hostname}`) && Path(`/mcp`)",
                "entryPoints": [entrypoint],
                "service": f"{name}-mcp",
                "middlewares": ["edge-rate-limit", "edge-strip-identity"],
            }

    return {"http": {"routers": routers, "services": services, "middlewares": middlewares}}


def cloudflared_ingress(data: dict[str, Any], node_name: str) -> dict[str, Any]:
    """Ingress rules only; tunnel identity and credentials stay in the private host config."""
    edge = data["nodes"][node_name]["edge"]
    ports = {name: value["port"] for name, value in edge["entrypoints"].items()}
    hosts: dict[str, int] = {}
    for key in ("authelia", "dashboard"):
        if edge.get(key):
            hosts[edge[key]["hostname"]] = ports[edge[key]["entrypoint"]]
    for service in data["services"].values():
        public = service.get("public", {})
        if public.get("enabled") and public.get("edge_node") == node_name:
            hosts[public["hostname"]] = ports[public["entrypoint"]]
    rules = [{"hostname": host, "service": f"http://127.0.0.1:{port}"} for host, port in sorted(hosts.items())]
    return {"ingress": [*rules, {"service": "http_status:404"}]}


def bridge_units(data: dict[str, Any], node_name: str) -> dict[str, str]:
    """systemd user socket/service pairs exposing host-loopback services on the Docker gateway."""
    edge = data["nodes"][node_name]["edge"]
    upstreams = []
    for service in data["services"].values():
        upstreams.append(service["upstream"])
        upstreams += [route["upstream"] for route in service.get("path_routes", [])]
        if service.get("public", {}).get("oauth_mcp"):
            upstreams.append(service["public"]["oauth_mcp"]["upstream"])
    units: dict[str, str] = {}
    for upstream in upstreams:
        bridge = upstream.get("bridge")
        if not bridge or upstream["node"] != node_name:
            continue
        name = f"agent-homelab-bridge-{bridge['port']}"
        requires = bridge.get("requires_unit")
        unit_deps = f"Requires={requires}\nAfter={requires}\n" if requires else ""
        units[f"{name}.socket"] = (
            "[Unit]\n"
            f"Description=Agent Homelab bridge {edge['docker_gateway']}:{bridge['port']}"
            f" -> 127.0.0.1:{upstream['port']}\n\n"
            "[Socket]\n"
            f"ListenStream={edge['docker_gateway']}:{bridge['port']}\n"
            "# The Docker gateway address appears after boot; without FreeBind the socket fails permanently.\n"
            "FreeBind=yes\n"
            "NoDelay=true\n"
            f"Service={name}.service\n\n"
            "[Install]\nWantedBy=sockets.target\n"
        )
        units[f"{name}.service"] = (
            "[Unit]\n"
            f"Description=Agent Homelab bridge proxy to 127.0.0.1:{upstream['port']}\n"
            f"{unit_deps}\n"
            "[Service]\n"
            f"ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:{upstream['port']}\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\n"
        )
    return units


def route_probes(data: dict[str, Any], node_name: str) -> list[dict[str, Any]]:
    """Unauthenticated public probes, including a forged-forwarded-host bypass check."""
    edge = data["nodes"][node_name]["edge"]
    auth_host = edge.get("authelia", {}).get("hostname")
    probes: list[dict[str, Any]] = []
    if auth_host:
        probes.append({"name": "authelia", "url": f"https://{auth_host}/", "method": "GET", "expect": [200]})

    def protected(name: str, hostname: str) -> None:
        url = f"https://{hostname}/"
        probes.append({"name": f"{name}-requires-sign-in", "url": url, "method": "GET", "expect": [302, 401]})
        if auth_host:
            probes.append(
                {
                    "name": f"{name}-forged-forwarded-host",
                    "url": url,
                    "method": "GET",
                    "headers": {"X-Forwarded-Host": auth_host},
                    "expect": [302, 401],
                }
            )

    if edge.get("dashboard"):
        protected("traefik-dashboard", edge["dashboard"]["hostname"])
    for name, service in sorted(data["services"].items()):
        public = service.get("public", {})
        if not public.get("enabled") or public.get("edge_node") != node_name:
            continue
        auth = public.get("auth", {})
        if auth.get("provider") == "authelia" and auth.get("policy") != "bypass":
            protected(name, public["hostname"])
        if public.get("oauth_mcp"):
            base = f"https://{public['hostname']}"
            probes.append(
                {
                    "name": f"{name}-mcp-metadata",
                    "url": f"{base}{OAUTH_METADATA_PATHS[1]}",
                    "method": "GET",
                    "expect": [200],
                }
            )
            probes.append(
                {
                    "name": f"{name}-mcp-challenge",
                    "url": f"{base}/mcp",
                    "method": "POST",
                    "body": "{}",
                    "headers": {"Content-Type": "application/json"},
                    "expect": [401],
                }
            )
    return probes


def authelia_access_rules(data: dict[str, Any], node_name: str) -> list[dict[str, str]]:
    edge = data["nodes"][node_name]["edge"]
    rules: dict[str, str] = {}
    if edge.get("authelia"):
        rules[edge["authelia"]["hostname"]] = "bypass"
    if edge.get("dashboard"):
        rules[edge["dashboard"]["hostname"]] = "two_factor"
    for service in data["services"].values():
        public = service.get("public", {})
        auth = public.get("auth", {})
        if public.get("enabled") and public.get("edge_node") == node_name and auth.get("provider") == "authelia":
            rules[public["hostname"]] = auth["policy"]
    return [{"domain": domain, "policy": policy} for domain, policy in sorted(rules.items())]


def edge_safety_problems(static: dict[str, Any], dynamic: dict[str, Any]) -> list[str]:
    """Every forward-auth router on an entrypoint that trusts forwarded headers must pin the host first."""
    trusting = {
        name
        for name, entrypoint in static.get("entryPoints", {}).items()
        if entrypoint.get("forwardedHeaders", {}).get("trustedIPs")
        or entrypoint.get("forwardedHeaders", {}).get("insecure")
    }
    http = dynamic.get("http", {})
    middlewares = http.get("middlewares", {})
    problems: list[str] = []
    for router_name, router in http.get("routers", {}).items():
        if not trusting.intersection(router.get("entryPoints", [])):
            continue
        chain = router.get("middlewares", [])
        hosts = re.findall(r"Host\(`([^`]+)`\)", router.get("rule", ""))
        for index, middleware in enumerate(chain):
            if "forwardAuth" not in middlewares.get(middleware, {}):
                continue
            if len(hosts) != 1:
                problems.append(f"{router_name}: forward-auth router must match exactly one Host")
                break
            pinned = False
            for earlier in chain[:index]:
                headers = middlewares.get(earlier, {}).get("headers", {}).get("customRequestHeaders", {})
                if (
                    headers.get("X-Forwarded-Host") == hosts[0]
                    and headers.get("X-Forwarded-Proto") == "https"
                    and all(headers.get(name) == "" for name in CLEARED_FORWARDED)
                ):
                    pinned = True
            if not pinned:
                problems.append(f"{router_name}: {middleware} runs without pinning X-Forwarded-Host to {hosts[0]}")
    return problems
