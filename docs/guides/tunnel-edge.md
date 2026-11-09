# Cloudflare Tunnel edge

Use this when a home server has no open inbound ports. Cloudflare terminates TLS and a `cloudflared` tunnel on the server delivers plain HTTP to Traefik:

```text
Internet -> Cloudflare -> cloudflared (host) -> Traefik on 127.0.0.1:<entrypoint port>
         -> bridge socket on the Docker gateway -> service on host 127.0.0.1
         |
         +-> Authelia forward-auth for protected routes
```

In plain English: visitors reach Cloudflare, the tunnel carries their request to this machine, Traefik checks sign-in with Authelia, then a small bridge hands the request to a service that only listens on the machine itself.

## Inventory

Give the edge node both roles and an `edge` block:

```yaml
nodes:
  edge:
    roles: [service_host, edge_gateway]
    connect: {address: 192.0.2.30, ssh_alias: edge}
    edge:
      mode: tunnel
      trusted_ips: [127.0.0.1/32, 198.51.100.1/32]   # the hop cloudflared traffic arrives from
      docker_gateway: 198.51.100.1                   # Docker network gateway for bridge sockets
      rate_limit: {average: 20, burst: 40}           # per client, keyed on Cf-Connecting-IP
      entrypoints:
        auth: {port: 9080}
        dashboard: {port: 9081}
        apps: {port: 9082}
      authelia: {hostname: auth.example.net, entrypoint: auth}
      dashboard: {hostname: traefik.example.net, entrypoint: dashboard}
services:
  notes:
    upstream:
      node: edge
      scheme: http
      host: 127.0.0.1
      port: 19080
      port_source: notes unit LISTEN=127.0.0.1:19080
      bridge: {port: 19081}
    public:
      enabled: true
      hostname: notes.example.net
      edge_node: edge
      entrypoint: apps
      auth: {provider: authelia, policy: two_factor}
      oauth_mcp:                                     # optional: OAuth-protected MCP endpoint
        upstream:
          node: edge
          scheme: http
          host: 127.0.0.1
          port: 19110
          port_source: oauth relay unit LISTEN=127.0.0.1:19110
          bridge: {port: 19111}
```

In plain English: the `edge` block says which local ports Traefik listens on and which hop to trust. Each service says where it really runs, which bridge port reaches it, and which public hostname and sign-in policy it gets.

`tests/fixtures/tunnel.yaml` is a complete example.

Optional settings:

| Setting | Effect |
|---|---|
| `public.aliases`, `edge.authelia.aliases`, `edge.dashboard.aliases` | Extra hostnames (for example a tailnet-only name) served by the same routes, each with its own host pin and Authelia rule. Aliases are not added to the Cloudflare Tunnel. |
| `entrypoints.<name>.tailnet_https_port` | Renders `tailscale/serve.sh` with the matching `tailscale serve --https=<port>` command (tailnet only, never Funnel). |
| `upstream.bridge.unit_name` | Keeps an existing systemd unit name. Every upstream on the same bridge port must use the same name. |
| `edge.secure_headers` | Replaces the default security headers. |
| `edge.docker_network` | Joins an existing external Docker network, such as the one Authelia already uses. |
| Top-level `x-*` keys | Hold YAML anchors for shared blocks; rendering ignores them. |

A hostname may appear only once per entrypoint across the portal, dashboard, services and aliases.

## What `render` produces for a tunnel node

| File | Purpose |
|---|---|
| `traefik/traefik.yaml` | Entrypoints on the given ports, trusting forwarded headers only from `trusted_ips`; a directory file provider. |
| `traefik/dynamic/services.yaml` | Routers, services and middlewares. |
| `compose.yaml` | Traefik published on `127.0.0.1` only, with the dynamic directory mounted (edits reload without a restart). |
| `cloudflared/ingress.yml` | The tunnel's `ingress:` rules. The tunnel ID and credentials stay in the private host config. |
| `systemd/agent-homelab-bridge-<port>.socket` / `.service` | User units that expose a host-loopback service on the Docker gateway, with `FreeBind=yes`. |
| `probes.json` | Unauthenticated probes that `agent-homelab verify` runs, including a forged-header bypass check. |
| `authelia/access_control.yml` | Access-control rules for review. Authelia itself (OIDC clients, MFA, secrets) stays operator-managed. |

## Safety rules

These are enforced at validation or render time:

- **Pinned host before forward-auth.** Traefik must trust forwarded headers from the tunnel hop, and that hop passes through whatever the client sent. Every Authelia-protected router therefore runs a middleware that sets `X-Forwarded-Host` to the router's own host and `X-Forwarded-Proto` to `https`, and clears client `X-Forwarded-Uri/Method/Prefix/Port`, before forward-auth. Without it, a forged `X-Forwarded-Host` naming a bypass domain (such as the Authelia host) makes Authelia allow a protected route. Rendering fails if any forward-auth router on a trusting entrypoint lacks this pin.
- **Identity headers stripped.** `Remote-User` and similar headers from clients are removed before forward-auth, so apps only see what Authelia sets.
- **Per-client rate limit.** The limit is keyed on `Cf-Connecting-IP`, not the tunnel's single source address.
- **Narrow trust.** `trusted_ips` broader than a /8 is rejected.
- **Bridges required.** A loopback upstream on a tunnel edge must declare a `bridge`, because the Traefik container cannot reach host loopback.
- **Unique ports.** Entrypoint ports and bridge ports must be unique per upstream.
- **MCP routes are separate.** OAuth MCP metadata and `/mcp` are routed without forward-auth, because the MCP server issues its own OAuth challenge.

## Check

```bash
agent-homelab validate --inventory homelab.yaml
agent-homelab render --inventory homelab.yaml --output rendered
agent-homelab verify --inventory homelab.yaml
AGENT_HOMELAB_DOCKER_TESTS=1 pytest tests/integration/test_tunnel_edge_docker.py
```

In plain English: the first three commands check the inventory, write the config files, and probe the live public routes, including the forged-header bypass. The last runs the rendered config in a real Traefik against a fake Authelia, and runs a control case without the host pin to prove the test can detect the bypass.

Installing the rendered files on a live node follows the guarded procedure in `homelab-maintenance`: back up, stage, validate, promote, verify and roll back on failure.
