# Publish an MCP service at the edge

Topology: `Internet → Cloudflare Tunnel → Traefik (127.0.0.1 published port) → bridge socket on the Docker network gateway → host MCP service on 127.0.0.1`.

Values in angle brackets are site-specific. Keep them in the private inventory, not in this repository.

## Before any live change

Steps 1–3 change shared edge services. Installing this skill grants no authority to make them. Make each change only under an explicit release for a declared node, and through the guarded procedure in `homelab-maintenance` and `homelab-service-ingress` (policy `docs/dev/policies/0003-remote-operations.md`):

- [ ] Declare the target node, SSH alias, config path and the exact apply operation.
- [ ] Record a baseline: run `scripts/check_mcp_route.py` for any existing MCP routes, check the health of the units you will touch, and capture the current routes.
- [ ] Back up every file you will edit next to it, with a dated suffix.
- [ ] Render the change to a staging copy and validate it (`cloudflared tunnel ingress validate`, Traefik config check, `systemd-analyze verify`) before promoting.
- [ ] Promote atomically, then reload or restart only the unit that owns the file.
- [ ] Verify with step 4 plus the baseline checks. If any check fails, restore the backup, reload, and report.
- [ ] Report the node, files, backup paths, validation command, reload result and probe output.

Authelia client changes belong in the issuer owner's single change window (see `authelia-clients.md`). Do not restart Authelia a second time for this procedure.

## 1. Tunnel hostname

Add one ingress rule before the catch-all in a staged copy of the cloudflared config, validate it, promote it, then restart cloudflared. A new hostname is picked up only after a restart. When cloudflared is a system unit, that needs sudo; run it interactively with `ssh -t <edge> 'sudo systemctl restart <cloudflared-unit>'`, because without `-t` sudo fails with "a terminal is required":

```yaml
ingress:
  - hostname: <mcp-host>
    service: http://127.0.0.1:<traefik-entry-port>
  - service: http_status:404
```

Create the DNS route for the tunnel with `cloudflared tunnel route dns <tunnel> <mcp-host>`. This changes public DNS, so record the change; roll it back by deleting that DNS record.

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

### 2a. MCP service on another machine (reverse SSH relay)

When the MCP service runs on a machine behind NAT (for example a home PC) and the edge node can't reach it, that machine dials out to the edge. The edge then treats the relay port as its local upstream:

```ini
# on the service machine: <name>-edge-relay.service (user unit)
[Unit]
After=<mcp-service>.service
Wants=<mcp-service>.service

[Service]
ExecStart=/usr/bin/ssh -NT -o BatchMode=yes -o ExitOnForwardFailure=yes -o ForwardAgent=no \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -R 127.0.0.1:<relay-port>:127.0.0.1:<mcp-port> <edge-ssh-alias>
Restart=always
RestartSec=10
```

On the edge, point the bridge socket's `systemd-socket-proxyd` at `127.0.0.1:<relay-port>` instead of the local service. In the private inventory this is the upstream `{node: <edge>, port: <relay-port>, bridge: {...}}`, so `agent-homelab render` produces the routers unchanged.

- Bind the remote side to `127.0.0.1` only. `ExitOnForwardFailure=yes` makes a taken port fail loudly instead of running with no forward.
- Before the relay is up, the route gives `502`/`504`. That's expected; `check_mcp_route.py` passes once the relay and the service both run.
- The relay forwards only the OAuth-validating front (the service that checks bearer tokens), never an unauthenticated internal listener.

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

If you do put Authelia forward-auth on another router behind the tunnel, pin `X-Forwarded-Host` to that router's host (and `X-Forwarded-Proto: https`) in a headers middleware before forward-auth. The entry point trusts forwarded headers from the tunnel hop, so a client-supplied `X-Forwarded-Host` naming a bypass domain would otherwise skip sign-in. `agent-homelab render` does this for tunnel edges and refuses configs without it; see `docs/guides/tunnel-edge.md`.

## 4. Check

```sh
python3 scripts/check_mcp_route.py https://<mcp-host>/mcp
```

Expect metadata `200` JSON naming the resource and Authelia issuer, and an unauthenticated `POST /mcp` returning `401` with a `Bearer resource_metadata=...` challenge. A `502` means the bridge socket or MCP service is down; a `302` to the login page means `/mcp` is wrongly behind forward-auth.
