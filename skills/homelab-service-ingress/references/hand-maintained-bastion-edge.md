# Edge gaps outside the generator: firewall, DNS without cert.pem, layer probes

Read this when publishing a host service through a Cloudflare Tunnel edge whose Traefik runs in a container, and the
route still fails after the edge files are in place. The edit procedure itself (declared node, baseline, dated
backups, staged copy, validation, atomic promotion, reload, rollback) is the guarded procedure in
`homelab-mcp-connector` [references/publish.md](../../homelab-mcp-connector/references/publish.md) under policy
`docs/dev/policies/0003-remote-operations.md`. Follow it unchanged; this file adds only the gaps it does not cover.

Placeholders: `<edge>` SSH alias, `<host>` public hostname, `<port>` loopback service port, `<gw>` Docker network
gateway address, `<bridge-port>` bridge socket port, `<br-iface>` Docker bridge interface, `<traefik>` container name.

## Probe each layer before changing anything

| Layer | Probe |
|---|---|
| Service on loopback | `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:<port>/` on `<edge>` |
| Bridge socket from the host | `curl ... http://<gw>:<bridge-port>/` |
| Bridge socket from the container | `docker exec <traefik> wget -q -O- -T 5 http://<gw>:<bridge-port>/` |
| Edge router | `curl -H 'Host: <host>' http://127.0.0.1:<traefik-entry-port>/` |
| Public | `curl https://<host>/` |

Probe only paths that are safe to request: a root path or a known refusal, never a secret path.

## Host firewall between the container and the bridge

If the host probe succeeds but the in-container probe times out, a host firewall that allows container → host traffic
per port is the first suspect. Confirm the rule set with the human (reading it usually needs root), then have the human
add one narrowly scoped rule, for example with ufw:

```sh
ssh -t <edge> 'sudo ufw allow in on <br-iface> to <gw> port <bridge-port> proto tcp comment "<name> bridge" && sudo ufw status | grep <bridge-port>'
```

Find `<br-iface>` with `ip -o -4 addr show | grep '<gw>/'`. Re-run the in-container probe afterwards. A Traefik access
log entry with status `499` and an origin duration equal to the client timeout is consistent with this. It is only a
hypothesis: slow handlers, cancellations and upstream timeouts produce the same entry, so let the layer probes decide.

## DNS when the edge has no origin certificate

`cloudflared tunnel route dns` needs `cert.pem`. When the edge has none, create the record through the Cloudflare API
or dashboard instead: a proxied `CNAME <host> → <tunnel-id>.cfargotunnel.com`, matching an existing tunnel host's
record. `<tunnel-id>` is the `tunnel:` value in the cloudflared config. It is a public DNS change: get an explicit yes,
record it, and roll back by deleting the record.
