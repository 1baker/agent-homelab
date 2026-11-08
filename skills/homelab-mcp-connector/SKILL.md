---
name: homelab-mcp-connector
description: Publishes an OAuth-protected remote MCP server through a homelab edge (Cloudflare Tunnel, Traefik, Authelia) and connects it to ChatGPT, Claude, Claude Code, Codex, Grok or Superhuman Go. Use when asked to expose an MCP server publicly, add an MCP connector to a chat app, or repeat an existing MCP connector setup for another client.
license: Apache-2.0
---

# Homelab MCP Connector

One MCP server, one canonical resource URL, many chat clients. The MCP server validates audience-bound JWT access tokens; Authelia is the authorization server; each chat app is a separately registered OAuth client.

## Reference files

| File | Read when |
|---|---|
| [references/publish.md](references/publish.md) | Routing a host MCP service through the tunnel, Traefik and a Docker-bridge socket proxy |
| [references/authelia-clients.md](references/authelia-clients.md) | Registering a chat app as an Authelia OIDC client |
| [references/clients.md](references/clients.md) | Connecting a specific chat app and finding its callback |

## Workflow

Copy and track:

- [ ] Confirm the MCP server already validates issuer, JWKS, exact resource audience, scopes and owner, and serves protected-resource metadata. A working login page is not an OAuth issuer.
- [ ] Pick the canonical resource URL (`https://<host>/mcp`) once; every client and token uses it.
- [ ] Publish: tunnel hostname, Traefik routers (metadata without Authelia, `/mcp` without Authelia forward-auth), host bridge socket with `FreeBind=yes`.
- [ ] Run `scripts/check_mcp_route.py https://<host>/mcp` and get PASS before touching any client.
- [ ] For each chat app, read its exact callback from that app's UI or official docs, then add one Authelia client for it.
- [ ] Validate and apply the Authelia change in the owner's maintenance window; existing sessions and clients must survive.
- [ ] Add the connector in the chat app and complete sign-in plus two-factor as the human.
- [ ] Prove the connection: initialize, tools/list and one scoped read-only tool call from that app.
- [ ] Add the route to the edge health check so a dead upstream is noticed.

## Validation loop

Classify a failure by layer before editing: tunnel hostname, Traefik router, bridge socket, MCP service, metadata, Authelia client/callback, token audience/scope, or client-side bug. `check_mcp_route.py` covers the first five; the rest need the client's real sign-in.

## Gotchas

- Authelia has no dynamic client registration. Never advertise a `registration_endpoint`; preregister every client.
- `/mcp` must not sit behind Authelia forward-auth. Bearer tokens are checked by the MCP server; forward-auth would redirect the client to a login page.
- A socket bound to the Docker bridge address fails at boot unless it has `FreeBind=yes`; the route then returns 502 until someone restarts it.
- Behind a tunnel, Traefik sees the bridge gateway as the client. Key rate limits on `Cf-Connecting-IP`, not the remote address.
- A connector that reports a generic internal error may be hiding an upstream 502; run the route check first.
- Callbacks differ per app and can change. Copy them from the app, not from another client or an old guide.
- Never put a client secret, token, authorization URL or callback code in chat, tickets or PRs.
- A green route check proves reachability and the auth challenge, not a working sign-in or tool call.

## Related skills

- Use `homelab-service-ingress` for ordinary browser services behind Authelia.
- Use `homelab-troubleshooter` for layered diagnosis.
- Use `homelab-maintenance` to add the route to recurring health checks.
