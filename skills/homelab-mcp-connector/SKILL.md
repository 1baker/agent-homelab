---
name: homelab-mcp-connector
description: Publishes an OAuth-protected remote MCP server through a homelab edge (Cloudflare Tunnel, Traefik, Authelia) and preregisters each chat app as an Authelia OIDC client. Use when asked to expose an MCP server publicly or to add an Authelia client for another chat app. Connecting a client to the published server belongs to mcp-onboarding; building the server's OAuth belongs to oauth-custom-mcp.
license: Apache-2.0
---

# Homelab MCP Connector

One MCP server, one canonical resource URL, many chat clients. The MCP server validates audience-bound JWT access tokens; Authelia is the authorization server; each chat app is a separately registered OAuth client.

This skill owns the middle stage only:

1. Build the server's OAuth validation with `oauth-custom-mcp`.
2. Publish it through the edge and register Authelia clients here.
3. Connect each client and prove it works with `mcp-onboarding`.

## Reference files

| File | Read when |
|---|---|
| [references/publish.md](references/publish.md) | Routing a host MCP service through the tunnel, Traefik and a Docker-bridge socket proxy |
| [references/authelia-clients.md](references/authelia-clients.md) | Registering a chat app as an Authelia OIDC client |
| [references/clients.md](references/clients.md) | Finding a chat app's callback and Authelia client type before registering it |

## Workflow

Copy and track:

- [ ] Confirm the MCP server already validates issuer, JWKS, exact resource audience, scopes and owner, and serves protected-resource metadata. A working login page is not an OAuth issuer.
- [ ] Pick the canonical resource URL (`https://<host>/mcp`) once; every client and token uses it.
- [ ] Publish: tunnel hostname, Traefik routers (metadata without Authelia, `/mcp` without Authelia forward-auth), host bridge socket with `FreeBind=yes`.
- [ ] Run `scripts/check_mcp_route.py https://<host>/mcp` and get PASS before touching any client.
- [ ] For each chat app, read its exact callback from that app's UI or official docs, then add one Authelia client for it.
- [ ] Validate and apply the Authelia change in the owner's maintenance window; existing sessions and clients must survive.
- [ ] Add the route to the edge health check so a dead upstream is noticed.
- [ ] Hand off to `mcp-onboarding` to add the connector in each app, complete the human sign-in and two-factor, and prove initialize, tools/list and one scoped tool call. This skill stops at a published route with a PASS check and registered clients.

## Validation loop

Classify a failure by layer before editing: tunnel hostname, Traefik router, bridge socket, MCP service, metadata, Authelia client/callback, token audience/scope, or client-side bug. `check_mcp_route.py` covers the first five; the rest need the client's real sign-in through `mcp-onboarding`. Fix edge-layer failures here.

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
- Use `oauth-custom-mcp` to build the MCP server's token validation and protected-resource metadata.
- Use `mcp-onboarding` to connect ChatGPT, Claude, Claude Code, Codex, Grok or Superhuman Go to the published server and prove a real tool call.
- Use `homelab-troubleshooter` for layered diagnosis.
- Use `homelab-maintenance` to add the route to recurring health checks.
