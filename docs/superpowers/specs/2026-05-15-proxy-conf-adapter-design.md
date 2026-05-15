# Proxy Conf Adapter — Design Spec

**Date:** 2026-05-15
**Target machine:** sc0rch@192.168.0.111 (Ubuntu 20.04)

---

## Overview

A CLI tool (`proxyctl`) that acts as a management layer over `sing-box` on a remote Ubuntu 20.04 server. The user maintains a library of proxy configs parsed from URI-format text files (vless://, vmess://, ss://, trojan://, hysteria2://), selects an active proxy via SSH, and sing-box runs it as either a SOCKS5/HTTP proxy port or a TUN transparent proxy.

---

## Architecture

```
~/.config/proxyctl/
├── proxies.json      ← library of all added proxies (parsed URI + metadata)
├── state.json        ← currently active proxy ID + mode (socks/tun)

/etc/sing-box/
└── active.json       ← generated sing-box config for the active proxy

/usr/local/bin/sing-box   ← sing-box binary
/usr/local/bin/proxyctl   ← Python CLI script (single file, stdlib only + requests)

systemd: sing-box.service
  ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/active.json
  Restart=on-failure
  User=root
```

**Ports exposed by sing-box:**

| Port | Type      |
|------|-----------|
| 7890 | HTTP proxy |
| 7891 | SOCKS5 proxy |
| 7892 | Mixed (HTTP + SOCKS5) |
| tun0 | TUN device (only when TUN mode is active) |

---

## CLI Commands

### Loading configs
```bash
proxyctl add file.txt            # parse all proxy URIs from a text file
proxyctl add "vless://..."       # add a single URI string
```

### Viewing the library
```bash
proxyctl list                    # table: ID | protocol | country | tag | host
proxyctl list --protocol vless   # filter by protocol
proxyctl list --country RU       # filter by country (parsed from flag emoji in tag)
proxyctl show <id>               # full parameters of a single proxy
```

### Activation
```bash
proxyctl use <id>                # switch to proxy <id> and restart sing-box
proxyctl use <id> --mode tun     # switch and enable TUN mode
proxyctl status                  # show active proxy + sing-box service status
```

### Testing
```bash
proxyctl test <id>               # TCP connect + latency for one proxy
proxyctl test-all                # test all proxies, print latency table (ok/fail/ms)
proxyctl test-all --timeout 5    # custom timeout in seconds
proxyctl test-active             # test the currently active proxy
```

### Service management
```bash
proxyctl start
proxyctl stop
proxyctl restart
proxyctl logs                    # last 50 lines from journald
```

### TUN mode
```bash
proxyctl tun on                  # enable TUN (requires root)
proxyctl tun off                 # disable TUN, revert to socks/http only
```

### Removing configs
```bash
proxyctl remove <id>             # remove one proxy from the library
proxyctl remove <id1> <id2> ...  # remove multiple proxies
proxyctl remove --all            # clear the entire library
proxyctl remove --protocol vless # remove all proxies with a given protocol
proxyctl remove --country RU     # remove all proxies matching a country
```
If the active proxy is removed, proxyctl warns and stops sing-box automatically.

### Installation
```bash
proxyctl install                 # download sing-box, create systemd unit, init dirs
```

---

## Input Format

Text file with one proxy URI per line. Supported schemes:

```
vless://UUID@host:port?params#tag
vmess://BASE64_JSON
trojan://password@host:port?params#tag
ss://BASE64@host:port#tag   OR   ss://METHOD:PASS@host:port#tag
hysteria2://password@host:port?params#tag
```

Tags contain country flag emojis (`🇷🇺 RUS`, `🇹🇷 TUR`, etc.) which are used to extract the country code. Blank lines and lines not starting with a known scheme are silently skipped.

---

## Config Converter

Each URI is parsed into a sing-box `outbound` JSON object and stored in `proxies.json`.

**Parsing strategy:**

| Protocol   | Method |
|------------|--------|
| vless://   | `urllib.parse.urlparse` + query params |
| trojan://  | `urllib.parse.urlparse` + query params |
| hysteria2//| `urllib.parse.urlparse` + query params |
| vmess://   | base64 decode → JSON object |
| ss://      | base64 decode OR `METHOD:PASS@host:port` |

**Generated `active.json` structure:**
```json
{
  "inbounds": [
    { "type": "http",  "listen": "0.0.0.0", "listen_port": 7890 },
    { "type": "socks", "listen": "0.0.0.0", "listen_port": 7891 },
    { "type": "mixed", "listen": "0.0.0.0", "listen_port": 7892 }
    // + tun inbound when TUN mode is active
  ],
  "outbounds": [
    { /* selected proxy outbound */ },
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],
  "route": {
    "final": "<selected-proxy-tag>"
  }
}
```

---

## Deployment Flow

**One-time setup from local machine:**
```bash
scp proxyctl.py sc0rch@192.168.0.111:/usr/local/bin/proxyctl
ssh sc0rch@192.168.0.111 'sudo proxyctl install'
```

**`proxyctl install` steps:**
1. Download latest sing-box release binary (linux-amd64) from GitHub releases
2. Install to `/usr/local/bin/sing-box`
3. Create `/etc/sing-box/` and `~/.config/proxyctl/`
4. Write `/etc/systemd/system/sing-box.service`
5. `systemctl daemon-reload && systemctl enable sing-box`

**Typical session:**
```bash
scp run_2026-05-13.txt sc0rch@192.168.0.111:~/
ssh sc0rch@192.168.0.111 'proxyctl add ~/run_2026-05-13.txt'
ssh sc0rch@192.168.0.111 'proxyctl list'
ssh sc0rch@192.168.0.111 'proxyctl test-all'
ssh sc0rch@192.168.0.111 'proxyctl use 5'
```

---

## Implementation Notes

- **Single Python file**, no pip dependencies except `requests` (for test-active HTTP check via proxy). All other stdlib.
- **proxies.json** stores both the raw URI and the parsed sing-box outbound fragment, so re-parsing is never needed.
- **state.json** stores `{ "active_id": 5, "mode": "socks" }`.
- **TUN mode** requires the sing-box service to run as root (already the case in the systemd unit).
- `proxyctl test <id>` does a TCP connect to the proxy server's host:port, not through the proxy. `proxyctl test-active` routes an HTTP request through the active proxy (via `requests` with `proxies={"http": "socks5://..."}`) to verify end-to-end.
- Country extraction: scan the tag string for a Unicode regional indicator pair (🇦🇿 = U+1F1E6 U+1F1FF) and map to ISO code.

---

## Error Handling

- Malformed URIs during `add`: skip with a warning, count at the end (`Added 412, skipped 3`).
- `use <id>` on nonexistent ID: exit with error message.
- sing-box fails to start: `proxyctl use` prints the last 10 log lines automatically.
- `remove` of active proxy: print warning, stop sing-box, remove from library.
