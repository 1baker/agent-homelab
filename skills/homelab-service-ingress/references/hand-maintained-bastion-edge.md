# Hand-maintained bastion edge (Cloudflare Tunnel → Traefik → host service)

Read this when the generator cannot map the edge node, for example when `agent-homelab plan` refuses because the
inventory has no `nodes.<edge>.deploy`, or when a generic apply would replace the whole live Traefik tree. Proven on
2026-11-17 publishing `derpy-tunnel` (work-tracker #254), following the existing `dot` route as the precedent.

## The four hops, and how to check each

| Hop | Live config | Check |
|---|---|---|
| Host service on loopback | its own unit | `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:PORT/` |
| Docker bridge → loopback | user units `NAME-relay-bridge.{socket,service}`: `ListenStream=172.18.0.1:BRIDGE`, `FreeBind=yes`, `systemd-socket-proxyd 127.0.0.1:PORT` | from the host: `curl http://172.18.0.1:BRIDGE/` |
| Traefik router | `~/bastion/traefik/<deployment>/dynamic/services.yaml` (file provider, `watch: true`, no restart) | from INSIDE the container: `docker exec traefik wget -q -O- -T 5 http://172.18.0.1:BRIDGE/` |
| Cloudflare Tunnel | `~/.cloudflared/homelab.yml` ingress (insert before the `http_status:404` catch-all) | public `curl https://HOST/` |

## Steps

1. Copy the closest existing route (socket and service units, router, service and middlewares). Take a timestamped
   `.bak` of every file before editing. Edit surgically and keep unrelated structures byte-identical.
2. `systemctl --user daemon-reload && systemctl --user enable --now NAME-relay-bridge.socket`.
3. Add the router and service to `services.yaml`. Use Authelia middlewares unless the service is a machine client that
   cannot log in. In that case the service itself must be the gate (for example a secret path), and the reason is
   recorded in the inventory.
4. Add the hostname to `homelab.yml`, then restart the tunnel. `cloudflared-homelab` is a **system** unit (`User=` the
   operator), so the restart needs the human's sudo:
   `ssh -t bastion 'sudo systemctl restart cloudflared-homelab && systemctl is-active cloudflared-homelab'`.
   All public hosts blip for a few seconds.
5. DNS: the bastion has no `cert.pem`, so `cloudflared tunnel route dns` fails. Create a proxied CNAME
   `HOST → <tunnel-uuid>.cfargotunnel.com` through the Cloudflare API, copying an existing host's record. The tunnel
   UUID is the `tunnel:` value in `homelab.yml`. Creating DNS is an outward-facing change and needs the human's explicit yes.
6. **Firewall:** ufw is active and allows Docker → host traffic per port. A new bridge port is dropped until the human
   runs, for example, `sudo ufw allow in on <br-iface> to 172.18.0.1 port BRIDGE proto tcp comment "NAME bridge"`.
   Find the interface with `ip -o -4 addr show | grep 172.18.0.1/`.

## Symptoms

- A public request hangs and Traefik's access log shows `DownstreamStatus 499` with `OriginDuration` equal to the client
  timeout, while the host can reach the bridge: the ufw rule is missing (step 6). Confirm with the in-container `wget`.
- Public `000` right after DNS creation: a resolver negative cache or the tunnel not restarted. Check `getent hosts`
  and step 4.
- Public `404` from Traefik (not the service): the router or Host rule is missing, or the dynamic file failed to load.
