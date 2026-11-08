# Publish an MCP service at the edge

Topology: `Internet → Cloudflare Tunnel → Traefik (127.0.0.1 published port) → bridge socket on the Docker network gateway → host MCP service on 127.0.0.1`.

Values in angle brackets are site-specific. Keep them in the private inventory, not in this repository.

## 1. Tunnel hostname

Add one ingress rule before the catch-all in the cloudflared config, then restart cloudflared:

```yaml
ingress:
  - hostname: <mcp-host>
    service: http://127.0.0.1:<traefik-entry-port>
  - service: http_status:404
```

Create the DNS route for the tunnel with `cloudflared tunnel route dns <tunnel> <mcp-host>`.

## 2. Bridge socket (host service → container network)

Traefik runs in a container and cannot reach the host's `127.0.0.1`. Proxy it from the Docker network gateway with a socket-activated `systemd-socket-proxyd` (user units shown):

```ini
# <name>-bridge.socket
[Socket]
ListenStream=<docker-gateway-ip>:<bridge-port>
FreeBind=yes
NoDelay=true
Service=<name>-bridge.service

[Install]
WantedBy=sockets.target
```

```ini
# <name>-bridge.service
[Unit]
Requires=<mcp-service>.service
After=<mcp-service>.service

[Service]
ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:<mcp-port>
NoNewPrivileges=yes
```

`FreeBind=yes` is required: at boot the socket starts before Docker creates the gateway address, and without it the unit fails permanently with `Cannot assign requested address`.

## 3. Traefik routers

The entry point must trust forwarded headers only from the tunnel and Docker networks. Two routers share the host; neither uses Authelia forward-auth:

```yaml
http:
  routers:
    <name>-oauth-metadata:
      entryPoints: [<entry>]
      rule: Host(`<mcp-host>`) && (Path(`/.well-known/oauth-protected-resource`) || Path(`/.well-known/oauth-protected-resource/mcp`))
      middlewares: [<per-client-rate-limit>, <strip-identity-headers>, <secure-headers>]
      service: <name>-mcp
    <name>-mcp:
      entryPoints: [<entry>]
      rule: Host(`<mcp-host>`) && Path(`/mcp`)
      middlewares: [<per-client-rate-limit>, <strip-identity-headers>]
      service: <name>-mcp
  services:
    <name>-mcp:
      loadBalancer:
        servers:
          - url: http://<docker-gateway-ip>:<bridge-port>
  middlewares:
    <per-client-rate-limit>:
      rateLimit:
        average: 20
        burst: 40
        sourceCriterion:
          requestHeaderName: Cf-Connecting-IP
```

Strip `Remote-User`-style identity headers on these routers so the MCP server never trusts a client-supplied identity. Any other path on the host can keep Authelia forward-auth for a browser UI.

## 4. Check

```sh
python3 scripts/check_mcp_route.py https://<mcp-host>/mcp
```

Expect metadata `200` JSON naming the resource and Authelia issuer, and an unauthenticated `POST /mcp` returning `401` with a `Bearer resource_metadata=...` challenge. A `502` means the bridge socket or MCP service is down; a `302` to the login page means `/mcp` is wrongly behind forward-auth.
