---
name: homelab-service-ingress
description: Registers and validates services behind Agent Homelab Traefik ingress, including direct or bastion-relayed HTTPS and Authelia protection. Use when asked to expose, publish, route, protect, update, or remove a homelab service.
license: Apache-2.0
---

# Homelab Service Ingress

The service inventory is the authority. Route reachability and application proxy correctness are separate gates.

## Reference files

| File | Read when |
|---|---|
| [references/application-proxy-checks.md](references/application-proxy-checks.md) | Validating an application after Traefik begins routing it |

## Workflow

Copy and track:

- [ ] Confirm the raw upstream responds on a reload-stable port.
- [ ] Locate the service runtime file that pins the port.
- [ ] Upsert the inventory with node, port, `port_source`, local host, public host, edge node, and auth policy.
- [ ] Validate the entire inventory.
- [ ] Render and inspect origin, edge, and Authelia output.
- [ ] On a Cloudflare Tunnel edge (`edge.mode: tunnel`), give a loopback upstream a `bridge` port and pick a tunnel `entrypoint`; check that `probes.json` includes the forged-forwarded-host probe for every protected host, and that `agent-homelab verify` passes it after install.
- [ ] Run node plans and dry-runs before apply.
- [ ] Apply the service host before the edge gateway in relay mode.
- [ ] Probe the origin with the public Host header.
- [ ] Verify public TLS and expected unauthenticated behavior.
- [ ] Check application redirects, cookies, callbacks, assets, WebSockets, and raw-port leakage.

Use `scripts/upsert-service.sh` for the common local-plus-public protected route. Use the CLI directly for other shapes.

## Validation loop

If routing fails, classify the failing layer before editing: raw upstream, origin router, relay reachability, edge router, authentication, or application canonical URL behavior.

## Gotchas

- Do not register an ephemeral development port unless it is intentionally pinned and declared with `allow_ephemeral_port`.
- A public `404` usually means the edge router or Host rule is absent; `502` usually means origin reachability failed.
- An unauthenticated `200` on a protected service means the auth boundary is missing.
- Fix absolute raw-port URLs in the application, not by hiding them with unrelated shared proxy rewrites.
- Update inventory and rerender; do not hand-edit installed generated YAML.

## Related skills

- Use `homelab-maintenance` for recurring drift and health checks.
- Use `homelab-troubleshooter` for layered diagnosis.
