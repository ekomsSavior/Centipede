# Centipede C2 - transport options

The c2d server listens on one TCP port and speaks WebSocket to bots and HTTP
to the operator browser/API. Nothing in the server depends on a specific
tunnel provider; pick any of the options below and point bots and operators
at the public URL. Pair every public exposure with `-token` and TLS where
possible.

## 1. cloudflared quick tunnel (built in, zero account)

The server can spawn a cloudflared quick tunnel itself:

```bash
./bin/c2d -addr :8443 -tunnel cloudflared -token "op-secret"
```

It prints the public `https://<random>.trycloudflare.com` URL once the
tunnel is up. WebSocket upgrades pass through unchanged, so the bot channel
works out of the box. Hostnames are random per start; for a fixed hostname
use a named cloudflared tunnel or a direct host.

## 2. Direct VPS with TLS (no third party)

Run behind Caddy or nginx on 443. Caddy one-liner:

```
your-domain.example {
    reverse_proxy 127.0.0.1:8443
}
```

Caddy terminates TLS and proxies WebSocket upgrades automatically. The
server can also terminate TLS itself with `-cert`/`-key`. Keep the c2d
listener bound to 127.0.0.1 when a front proxy is used:
`-addr 127.0.0.1:8443`.

## 3. CDN fronting for the operator API/dashboard

`deploy/cloudflare_worker.js` routes on the Host header: requests for your
hidden hostname are forwarded to the c2d origin, everyone else gets a decoy
page. Useful for the REST API and dashboard; note that transparent WebSocket
proxying through a Worker requires the Workers WebSocket-origin bridging
pattern, so the bot channel is better served by cloudflared or a direct
host. `deploy/nginx.conf` is a plain nginx TLS + WebSocket reverse proxy
sample for the same fronting idea without a CDN.

## 4. Notes

- All transports are interchangeable: bots only need the public WS URL
  (`wss://host/ws/bot`) and operators the matching HTTP(S) URL.
- `-token` gates `/api` and the operator `/ws`; the login endpoint is
  `/login?token=...` which sets an HttpOnly cookie for the dashboard.
- Discord notifications are outbound only and never required for C2
  operation.
