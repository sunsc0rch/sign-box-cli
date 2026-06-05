#!/usr/bin/env python3
"""proxyctl - CLI manager for sing-box proxy on Ubuntu server"""

import argparse
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

try:
    import requests as _requests_module
    requests = _requests_module
except ImportError:
    requests = None  # type: ignore

def _config_home() -> Path:
    """Return the real user's home when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()

CONFIG_DIR = _config_home() / ".config" / "proxyctl"
PROXIES_FILE = CONFIG_DIR / "proxies.json"
STATE_FILE = CONFIG_DIR / "state.json"
SING_BOX_CONFIG = Path("/etc/sing-box/active.json")
SING_BOX_BIN = "/usr/local/bin/sing-box"
SING_BOX_SERVICE_PATH = Path("/etc/systemd/system/sing-box.service")
SING_BOX_UNIT = """\
[Unit]
Description=sing-box proxy service
After=network-online.target
Wants=network-online.target
Before=docker.service cloudflared.service

[Service]
ExecStart={bin} run -c /etc/sing-box/active.json
Restart=on-failure
RestartSec=3s
User=root

[Install]
WantedBy=multi-user.target
"""
PROBE_ACTIVE_PORT     = 7890   # port of the running sing-box instance
PROBE_TEMP_PORT       = 17890  # temp port used when probing a single non-active proxy
PROBE_TEMP_PORT_BASE  = 17900  # base of port pool for bulk probing (17900..17900+CONCURRENCY-1)
PROBE_BULK_CONCURRENCY = 8     # max simultaneous temp sing-box processes during probe-all
PROBE_BULK_TIMEOUT    = 8.0    # seconds per proxy during probe-all


# ── URI Parsers ──────────────────────────────────────────────────────────────

def parse_vless(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless-{host}"
    params = dict(urllib.parse.parse_qsl(parsed.query))

    outbound: dict = {
        "type": "vless",
        "tag": tag,
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }

    flow = params.get("flow", "")
    if flow:
        outbound["flow"] = flow

    security = params.get("security", "")
    tls: dict = {}
    if security in ("tls", "reality"):
        tls["enabled"] = True
        sni = params.get("sni", "")
        if sni:
            tls["server_name"] = sni
        fp = params.get("fp", "")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            reality: dict = {"enabled": True}
            pbk = params.get("pbk", "")
            sid = params.get("sid", "")
            if pbk:
                reality["public_key"] = pbk
            if sid:
                reality["short_id"] = sid
            tls["reality"] = reality
        elif params.get("allowInsecure") == "1":
            tls["insecure"] = True
    if tls:
        outbound["tls"] = tls

    transport_type = params.get("type", "tcp")
    if transport_type == "ws":
        transport: dict = {
            "type": "ws",
            "path": urllib.parse.unquote(params.get("path", "/")),
        }
        host_header = params.get("host", "")
        if host_header:
            transport["headers"] = {"Host": host_header}
        ed = params.get("ed", "")
        if ed:
            try:
                transport["max_early_data"] = int(ed)
                transport["early_data_header_name"] = params.get("eh", "Sec-WebSocket-Protocol")
            except ValueError:
                pass
        outbound["transport"] = transport
    elif transport_type == "grpc":
        transport = {"type": "grpc"}
        svc = params.get("serviceName", "")
        if svc:
            transport["service_name"] = svc
        outbound["transport"] = transport

    return outbound

def parse_vmess(uri: str) -> dict:
    b64 = uri[8:]  # strip "vmess://"
    b64 += "=" * (-len(b64) % 4)
    data = json.loads(base64.b64decode(b64).decode())

    host = data.get("add", "")
    port = int(data.get("port", 443))
    tag = data.get("ps", f"vmess-{host}")
    net = data.get("net", "tcp")

    outbound: dict = {
        "type": "vmess",
        "tag": tag,
        "server": host,
        "server_port": port,
        "uuid": data.get("id", ""),
        "security": data.get("scy", "auto"),
        "alter_id": int(data.get("aid", 0)),
    }

    if data.get("tls") == "tls":
        sni = data.get("sni") or data.get("host", "")
        tls: dict = {"enabled": True}
        if sni:
            tls["server_name"] = sni
        outbound["tls"] = tls

    if net == "ws":
        transport: dict = {"type": "ws", "path": data.get("path", "/")}
        ws_host = data.get("host", "")
        if ws_host:
            transport["headers"] = {"Host": ws_host}
        outbound["transport"] = transport
    elif net == "grpc":
        svc = data.get("path", "")
        transport = {"type": "grpc"}
        if svc:
            transport["service_name"] = svc
        outbound["transport"] = transport

    return outbound

def parse_ss(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""

    if parsed.hostname:
        # ss://BASE64@host:port or ss://method:password@host:port
        userinfo = parsed.username or ""
        try:
            padded = userinfo + "=" * (-len(userinfo) % 4)
            decoded = base64.b64decode(padded).decode()
            method, password = decoded.split(":", 1)
        except Exception:
            method = userinfo
            password = urllib.parse.unquote(parsed.password or "")
        host = parsed.hostname
        port = parsed.port
    else:
        # ss://BASE64 (no @) — legacy format
        b64_part = uri.split("//", 1)[1].split("#")[0]
        b64_part += "=" * (-len(b64_part) % 4)
        decoded = base64.b64decode(b64_part).decode()
        user_part, host_part = decoded.rsplit("@", 1)
        method, password = user_part.split(":", 1)
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_part, 443

    tag = tag or f"ss-{host}"
    return {
        "type": "shadowsocks",
        "tag": tag,
        "server": host,
        "server_port": int(port),
        "method": method,
        "password": password,
    }

def parse_trojan(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
    params = dict(urllib.parse.parse_qsl(parsed.query))
    host = parsed.hostname
    port = parsed.port
    password = urllib.parse.unquote(parsed.username or "")
    tag = tag or f"trojan-{host}"

    outbound: dict = {
        "type": "trojan",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": password,
    }

    tls: dict = {"enabled": True}
    sni = params.get("sni", "")
    if sni:
        tls["server_name"] = sni
    if params.get("allowInsecure") == "1":
        tls["insecure"] = True
    outbound["tls"] = tls

    transport_type = params.get("type", "tcp")
    if transport_type == "ws":
        transport: dict = {"type": "ws", "path": params.get("path", "/")}
        host_header = params.get("host", "")
        if host_header:
            transport["headers"] = {"Host": host_header}
        outbound["transport"] = transport

    return outbound

def parse_hysteria2(uri: str) -> dict:
    normalized = uri.replace("hy2://", "hysteria2://", 1)
    parsed = urllib.parse.urlparse(normalized)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
    params = dict(urllib.parse.parse_qsl(parsed.query))
    host = parsed.hostname
    port = parsed.port
    password = urllib.parse.unquote(parsed.username or "")
    tag = tag or f"hy2-{host}"

    outbound: dict = {
        "type": "hysteria2",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": password,
    }

    tls: dict = {"enabled": True}
    sni = params.get("sni", "")
    if sni:
        tls["server_name"] = sni
    if params.get("insecure") == "1":
        tls["insecure"] = True
    outbound["tls"] = tls

    return outbound

def extract_country(tag: str) -> str:
    # Regional indicator symbols: U+1F1E6 (A) to U+1F1FF (Z)
    # Two consecutive indicators = one country flag
    flags = re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", tag)
    if not flags:
        return ""
    return "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in flags[0])

def parse_uri(uri: str) -> dict:
    uri = uri.strip()
    if uri.startswith("vless://"):
        return parse_vless(uri)
    elif uri.startswith("vmess://"):
        return parse_vmess(uri)
    elif uri.startswith("ss://"):
        return parse_ss(uri)
    elif uri.startswith("trojan://"):
        return parse_trojan(uri)
    elif uri.startswith("hysteria2://") or uri.startswith("hy2://"):
        return parse_hysteria2(uri)
    else:
        raise ValueError(f"Unsupported URI scheme: {uri[:30]!r}")


def build_library_entry(uri: str, outbound: dict) -> dict:
    normalized = uri.replace("hy2://", "hysteria2://", 1)
    parsed = urllib.parse.urlparse(normalized)
    fragment = urllib.parse.unquote(parsed.fragment or "")
    protocol = outbound["type"]
    if protocol == "shadowsocks":
        protocol = "ss"
    return {
        "protocol": protocol,
        "tag": outbound.get("tag", ""),
        "host": outbound.get("server", ""),
        "port": outbound.get("server_port", 0),
        "country": extract_country(fragment),
        "raw_uri": uri,
        "outbound": outbound,
    }


# ── Proxy Library ────────────────────────────────────────────────────────────

class ProxyLibrary:
    def __init__(self, path: Path = PROXIES_FILE):
        self.path = path
        self._data: dict = {"next_id": 1, "proxies": {}}

    def load(self) -> "ProxyLibrary":
        if self.path.exists():
            self._data = json.loads(self.path.read_text())
        return self

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False))

    def add(self, entry: dict) -> int:
        existing = {int(k) for k in self._data["proxies"]}
        id_ = next(i for i in range(1, len(existing) + 2) if i not in existing)
        self._data["proxies"][str(id_)] = entry
        self._data["next_id"] = max(existing | {id_}, default=0) + 1
        return id_

    def get(self, id_: int) -> Optional[dict]:
        return self._data["proxies"].get(str(id_))

    def all(self) -> list:
        return sorted([(int(k), v) for k, v in self._data["proxies"].items()])

    def set_live(self, id_: int, value: Optional[bool]):
        entry = self.get(id_)
        if entry is not None:
            entry["live"] = value
            self.save()

    def remove(self, id_: int) -> bool:
        key = str(id_)
        if key in self._data["proxies"]:
            del self._data["proxies"][key]
            return True
        return False

    def clear(self):
        self._data["proxies"] = {}

    def compact(self) -> dict:
        """Renumber all proxies starting from 1. Returns {old_id: new_id}."""
        old_proxies = sorted(self._data["proxies"].items(), key=lambda x: int(x[0]))
        mapping = {}
        new_proxies = {}
        for new_id, (old_key, entry) in enumerate(old_proxies, start=1):
            mapping[int(old_key)] = new_id
            new_proxies[str(new_id)] = entry
        self._data["proxies"] = new_proxies
        self._data["next_id"] = len(new_proxies) + 1
        return mapping


# ── State ────────────────────────────────────────────────────────────────────

_STATE_DEFAULTS: dict = {
    "active_id": None,
    "mode": "socks",
    "dns": "tls://1.1.1.1",
    "utls": "chrome",
}

def load_state() -> dict:
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        for k, v in _STATE_DEFAULTS.items():
            if state.get(k) is None and v is not None:
                state[k] = v
        return state
    return dict(_STATE_DEFAULTS)


def save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ── Config Generator ─────────────────────────────────────────────────────────

def _build_dns_server(address: str) -> dict:
    """Convert user DNS string to sing-box 1.12+ server object (tag+type+server)."""
    entry: dict = {"tag": "dns-main"}
    if address.startswith("tls://"):
        entry["type"] = "tls"
        entry["server"] = address[6:]
    elif address.startswith("https://"):
        parsed = urllib.parse.urlparse(address)
        entry["type"] = "https"
        entry["server"] = parsed.hostname
        if parsed.path and parsed.path != "/":
            entry["path"] = parsed.path
    elif address.startswith("h3://"):
        parsed = urllib.parse.urlparse(address)
        entry["type"] = "h3"
        entry["server"] = parsed.hostname
        if parsed.path and parsed.path != "/":
            entry["path"] = parsed.path
    else:
        # plain IP or IP:port
        if ":" in address:
            host, port = address.rsplit(":", 1)
            entry["type"] = "udp"
            entry["server"] = host
            entry["server_port"] = int(port)
        else:
            entry["type"] = "udp"
            entry["server"] = address
    return entry

def generate_active_config(
    outbound: dict,
    mode: str = "socks",
    bypass: Optional[list] = None,
    dns: Optional[str] = None,
    clash_api: bool = False,
    utls: Optional[str] = None,
) -> dict:
    inbounds = [
        {"type": "http",  "tag": "http-in",  "listen": "::", "listen_port": 7890},
        {"type": "socks", "tag": "socks-in", "listen": "::", "listen_port": 7891},
        {"type": "mixed", "tag": "mixed-in", "listen": "::", "listen_port": 7892},
    ]
    if mode == "tun":
        tun_inbound: dict = {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30"],
            "auto_route": True,
            "strict_route": True,
        }
        # Exclude private subnets (LAN, loopback) so remote SSH management
        # and local traffic bypass TUN. Also exclude the proxy server IP so
        # sing-box can reach it directly without looping through the tunnel.
        route_exclude = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
        ]
        proxy_server = outbound.get("server", "")
        if proxy_server and not proxy_server.startswith(("10.", "172.", "192.168.")):
            route_exclude.append(f"{proxy_server}/32")
        tun_inbound["route_exclude_address"] = route_exclude
        inbounds.append(tun_inbound)

    if utls and outbound.get("type") in ("vless", "trojan", "vmess"):
        tls = outbound.setdefault("tls", {"enabled": True})
        if not tls.get("utls"):
            tls["utls"] = {"enabled": True, "fingerprint": utls}

    if utls and outbound.get("type") == "vless":
        outbound.setdefault("packet_encoding", "xudp")

    route: dict = {"final": outbound["tag"]}
    route_rules: list = []
    if mode == "tun":
        # sniff moved from inbound field to route rule action in sing-box 1.13
        route_rules.append({"action": "sniff"})
    if bypass:
        route_rules.append({"ip_is_private": True, "outbound": "direct"})
        rule_sets = []
        for country in bypass:
            country = country.lower()
            route_rules.append({
                "rule_set": [f"geoip-{country}", f"geosite-{country}"],
                "outbound": "direct",
            })
            rule_sets += [
                {
                    "type": "remote",
                    "tag": f"geoip-{country}",
                    "format": "binary",
                    "url": f"https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-{country}.srs",
                    "update_interval": "1d",
                },
                {
                    "type": "remote",
                    "tag": f"geosite-{country}",
                    "format": "binary",
                    "url": f"https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-{country}.srs",
                    "update_interval": "1d",
                },
            ]
        route["rule_set"] = rule_sets
    if route_rules:
        route["rules"] = route_rules

    config: dict = {
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": route,
    }

    if dns:
        config["dns"] = {
            "servers": [_build_dns_server(dns)],
            "final": "dns-main",
        }

    if clash_api:
        config["experimental"] = {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": "",
            }
        }

    return config


# ── Service Management ───────────────────────────────────────────────────────

def service_action(action: str, silent: bool = False):
    # Try sudo -n first (non-interactive, avoids polkit prompt in TUI/SSH).
    # Fall back to plain systemctl if sudo is not available.
    for cmd in (
        ["sudo", "-n", "systemctl", action, "sing-box"],
        ["systemctl", action, "sing-box"],
    ):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return
        # sudo not configured — try plain systemctl next iteration
        if cmd[0] == "sudo":
            continue
        if not silent:
            print(f"Error running systemctl {action}: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)


def cmd_logs(args):
    os.execvp("journalctl", ["journalctl", "-u", "sing-box", "-n", "50", "--no-pager"])


# ── TCP Test ─────────────────────────────────────────────────────────────────

def tcp_test(host: str, port: int, timeout: float = 5.0) -> Optional[float]:
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return (time.time() - start) * 1000
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def http_probe(proxy_url: str = "http://127.0.0.1:7890", timeout: float = 15.0):
    """HTTP probe through proxy. Returns (ok, message, ms).

    Step 1: connectivity check via gstatic generate_204 (fast, globally reliable).
    Step 2: best-effort IP lookup via ip-api.com (skipped if slow/blocked).
    """
    import urllib.request
    import json as _json

    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)

    # Step 1: connectivity
    try:
        start = time.time()
        with opener.open("http://connectivitycheck.gstatic.com/generate_204",
                         timeout=timeout) as resp:
            ms = (time.time() - start) * 1000
            if resp.status not in (200, 204):
                return False, f"HTTP {resp.status}", ms
    except Exception as e:
        return False, str(e), 0.0

    # Step 2: IP info (best-effort, short timeout)
    try:
        with opener.open("http://ip-api.com/json?fields=query,country,isp",
                         timeout=5.0) as resp:
            data = _json.loads(resp.read().decode())
        ip = data.get("query", "?")
        country = data.get("country", "?")
        isp = data.get("isp", "?")
        return True, f"{ip} | {country} | {isp} | {ms:.0f}ms", ms
    except Exception:
        return True, f"OK | {ms:.0f}ms (IP lookup unavailable)", ms


def _probe_via_temp_singbox(
    outbound: dict,
    utls: Optional[str] = None,
    timeout: float = 15.0,
    port: int = PROBE_TEMP_PORT,
):
    """Probe a non-active proxy by spawning a temporary sing-box process.

    Starts sing-box on PROBE_TEMP_PORT, waits up to 5 s for it to bind,
    runs http_probe through it, then terminates the process.
    Returns (ok, msg, ms) — same as http_probe.
    """
    import copy, json as _json, tempfile

    out = copy.deepcopy(outbound)
    if utls and out.get("type") in ("vless", "trojan", "vmess"):
        tls = out.setdefault("tls", {"enabled": True})
        if not tls.get("utls"):
            tls["utls"] = {"enabled": True, "fingerprint": utls}
    if utls and out.get("type") == "vless":
        out.setdefault("packet_encoding", "xudp")

    config = {
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        ],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
        "route": {"final": out["tag"]},
    }

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="proxyctl_probe_", delete=False
    )
    try:
        _json.dump(config, tmp)
        tmp.close()

        proc = subprocess.Popen(
            [SING_BOX_BIN, "run", "-c", tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 5.0
            ready = False
            while time.time() < deadline:
                try:
                    s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                    s.close()
                    ready = True
                    break
                except OSError:
                    time.sleep(0.1)

            if not ready:
                return False, "sing-box failed to start within 5 s", 0.0

            return http_probe(f"http://127.0.0.1:{port}", timeout)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ── CLI Commands ─────────────────────────────────────────────────────────────

def cmd_compact(args):
    lib = ProxyLibrary(PROXIES_FILE).load()
    if not lib.all():
        print("Library is empty.")
        return
    mapping = lib.compact()
    lib.save()

    state = load_state()
    active_id = state.get("active_id")
    if active_id is not None and active_id in mapping:
        state["active_id"] = mapping[active_id]
        save_state(state)

    print(f"Compacted {len(mapping)} proxies: IDs now 1–{len(mapping)}")
    if active_id is not None and active_id in mapping:
        print(f"Active proxy: #{active_id} → #{mapping[active_id]}")


def cmd_add(args):
    source = args.source
    uris: list = []

    if source.startswith(("vless://", "vmess://", "ss://", "trojan://", "hysteria2://", "hy2://")):
        uris = [source]
    else:
        path = Path(source)
        if not path.exists():
            print(f"Error: file not found: {source}", file=sys.stderr)
            sys.exit(1)
        uris = path.read_text(encoding="utf-8").splitlines()

    lib = ProxyLibrary(PROXIES_FILE).load()
    added = 0
    skipped = 0

    for uri in uris:
        uri = uri.strip()
        if not uri:
            continue
        try:
            outbound = parse_uri(uri)
            entry = build_library_entry(uri, outbound)
            lib.add(entry)
            added += 1
        except Exception as e:
            print(f"  skip: {uri[:60]!r} — {e}", file=sys.stderr)
            skipped += 1

    lib.save()
    msg = f"Added {added}"
    if skipped:
        msg += f", skipped {skipped}"
    print(msg)


def cmd_list(args):
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxies = lib.all()

    if getattr(args, "protocol", None):
        proxies = [(id_, v) for id_, v in proxies if v["protocol"] == args.protocol]
    if getattr(args, "country", None):
        proxies = [(id_, v) for id_, v in proxies if v["country"] == args.country.upper()]

    if not proxies:
        print("No proxies found.")
        return

    print(f"{'ID':>4}  {'Protocol':<14}  {'Country':<4}  {'Host':<38}  {'Port'}  {'L':<1}  Tag")
    print("─" * 92)
    for id_, v in proxies:
        live = v.get("live")
        live_sym = "✓" if live is True else "✗" if live is False else "·"
        print(
            f"{id_:>4}  {v['protocol']:<14}  {v.get('country') or '??':<4}  "
            f"{v['host']:<38}  {v['port']:<6}  {live_sym}  {v['tag'][:40]}"
        )


def cmd_show(args):
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(args.id)
    if not proxy:
        print(f"Error: proxy {args.id} not found.", file=sys.stderr)
        sys.exit(1)
    print(f"ID:       {args.id}")
    print(f"Protocol: {proxy['protocol']}")
    print(f"Tag:      {proxy['tag']}")
    print(f"Host:     {proxy['host']}:{proxy['port']}")
    print(f"Country:  {proxy.get('country') or '(unknown)'}")
    print(f"URI:      {proxy['raw_uri'][:80]}")
    print("\nOutbound config:")
    print(json.dumps(proxy["outbound"], indent=2, ensure_ascii=False))


# ── System Proxy ─────────────────────────────────────────────────────────────

_SYSPROXY_KEYS = {
    "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY"
}
_NO_PROXY_LIST = "localhost,127.0.0.1,::1"


def _gsettings_env() -> dict:
    env = os.environ.copy()
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{os.getuid()}/bus"
    return env


def _set_gnome_proxy(enable: bool) -> bool:
    if not shutil.which("gsettings"):
        return False
    env = _gsettings_env()
    try:
        if enable:
            cmds = [
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
                ["gsettings", "set", "org.gnome.system.proxy.http", "host", "127.0.0.1"],
                ["gsettings", "set", "org.gnome.system.proxy.http", "port", "7890"],
                ["gsettings", "set", "org.gnome.system.proxy.https", "host", "127.0.0.1"],
                ["gsettings", "set", "org.gnome.system.proxy.https", "port", "7890"],
                ["gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"],
                ["gsettings", "set", "org.gnome.system.proxy.socks", "port", "7891"],
                ["gsettings", "set", "org.gnome.system.proxy", "ignore-hosts",
                 "['localhost', '127.0.0.0/8', '::1']"],
            ]
        else:
            cmds = [["gsettings", "set", "org.gnome.system.proxy", "mode", "none"]]
        for cmd in cmds:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True)
            if r.returncode != 0:
                return False
        return True
    except Exception:
        return False


def _set_env_proxy(enable: bool) -> bool:
    env_file = Path("/etc/environment")
    try:
        text = env_file.read_text() if env_file.exists() else ""
    except OSError:
        return False
    lines = [l for l in text.splitlines()
             if not any(l.startswith(k + "=") for k in _SYSPROXY_KEYS)]
    if enable:
        proxy_val = "http://127.0.0.1:7890"
        lines += [
            f"http_proxy={proxy_val}",
            f"https_proxy={proxy_val}",
            f"HTTP_PROXY={proxy_val}",
            f"HTTPS_PROXY={proxy_val}",
            f"no_proxy={_NO_PROXY_LIST}",
            f"NO_PROXY={_NO_PROXY_LIST}",
        ]
    new_content = "\n".join(lines) + ("\n" if lines else "")
    try:
        tmp = env_file.with_suffix(".tmp")
        tmp.write_text(new_content)
        os.replace(tmp, env_file)
        return True
    except OSError:
        pass
    # Fall back to sudo tee for non-root users
    r = subprocess.run(
        ["sudo", "tee", str(env_file)],
        input=new_content, capture_output=True, text=True,
    )
    return r.returncode == 0


def set_sysproxy(enable: bool) -> None:
    gnome_ok = _set_gnome_proxy(enable)
    env_ok = _set_env_proxy(enable)
    word = "enabled" if enable else "disabled"
    if gnome_ok:
        print(f"  GNOME proxy: {word}")
    if env_ok:
        print(f"  /etc/environment: {word}")
    if not gnome_ok and not env_ok:
        print(
            "  Warning: could not set system proxy "
            "(gsettings unavailable or no write access to /etc/environment)",
            file=sys.stderr,
        )
    state = load_state()
    state["sysproxy"] = enable
    save_state(state)


def cmd_sysproxy(args):
    if args.action == "on":
        set_sysproxy(True)
        print("System proxy: on → http://127.0.0.1:7890 / socks5://127.0.0.1:7891")
    elif args.action == "off":
        set_sysproxy(False)
        print("System proxy: off")
    elif args.action == "status":
        state = load_state()
        active = state.get("sysproxy", False)
        print(f"System proxy: {'on' if active else 'off'}")
        if shutil.which("gsettings"):
            try:
                r = subprocess.run(
                    ["gsettings", "get", "org.gnome.system.proxy", "mode"],
                    env=_gsettings_env(), capture_output=True, text=True,
                )
                if r.returncode == 0:
                    print(f"  GNOME: {r.stdout.strip()}")
            except Exception:
                pass
        env_file = Path("/etc/environment")
        if env_file.exists():
            content = env_file.read_text()
            has_proxy = any(f"{k}=" in content for k in _SYSPROXY_KEYS)
            print(f"  /etc/environment: {'proxy vars set' if has_proxy else 'no proxy vars'}")


def _resolve_use_settings(args, state: dict) -> tuple:
    """Resolve bypass/dns/clash_api from CLI args, falling back to existing state."""
    raw_bypass = getattr(args, "bypass", None)
    if raw_bypass is None:
        bypass = state.get("bypass") or []
    elif raw_bypass.lower() == "off":
        bypass = []
    else:
        bypass = [c.strip().lower() for c in raw_bypass.split(",") if c.strip()]

    raw_dns = getattr(args, "dns", None)
    if raw_dns is None:
        dns = state.get("dns")
    elif raw_dns.lower() == "off":
        dns = None
    else:
        dns = raw_dns

    raw_clash = getattr(args, "clash_api", None)
    if raw_clash is None:
        clash_api = state.get("clash_api", False)
    else:
        clash_api = raw_clash == "on"

    raw_utls = getattr(args, "utls", None)
    if raw_utls is None:
        utls = state.get("utls")
    elif raw_utls.lower() == "off":
        utls = None
    else:
        utls = raw_utls.lower()

    return bypass, dns, clash_api, utls


def cmd_use(args):
    state = load_state()
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(args.id)
    if not proxy:
        print(f"Error: proxy {args.id} not found.", file=sys.stderr)
        sys.exit(1)

    bypass, dns, clash_api, utls = _resolve_use_settings(args, state)

    config = generate_active_config(proxy["outbound"], mode=args.mode,
                                    bypass=bypass, dns=dns, clash_api=clash_api, utls=utls)
    SING_BOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = SING_BOX_CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    os.replace(tmp, SING_BOX_CONFIG)

    state.update({
        "active_id": args.id,
        "mode": args.mode,
        "bypass": bypass,
        "dns": dns,
        "clash_api": clash_api,
        "utls": utls,
    })
    save_state(state)

    service_action("restart")
    deadline = time.time() + 5
    while time.time() < deadline:
        result = subprocess.run(
            ["systemctl", "is-active", "sing-box"], capture_output=True, text=True
        )
        status = result.stdout.strip()
        if status == "active":
            break
        if status in ("failed", "inactive"):
            print("sing-box failed to start. Last logs:")
            subprocess.run(["journalctl", "-u", "sing-box", "-n", "10", "--no-pager"])
            sys.exit(1)
        time.sleep(0.5)
    else:
        print("sing-box did not become active within 5s. Last logs:")
        subprocess.run(["journalctl", "-u", "sing-box", "-n", "10", "--no-pager"])
        sys.exit(1)

    summary_parts = [
        f"Active: [{args.id}] {proxy['tag']}",
        f"{proxy['protocol']} | {proxy['host']}:{proxy['port']}",
        f"mode={args.mode}",
    ]
    if bypass:
        summary_parts.append(f"bypass={','.join(bypass)}")
    if dns:
        summary_parts.append(f"dns={dns}")
    if clash_api:
        summary_parts.append("clash-api=:9090")
    if utls:
        summary_parts.append(f"utls={utls}")
    print(" | ".join(summary_parts))
    print("Setting system proxy...")
    set_sysproxy(True)


def cmd_stop(args):
    service_action("stop")
    set_sysproxy(False)


def cmd_status(args):
    state = load_state()
    active_id = state.get("active_id")

    if active_id is None:
        print("No active proxy.")
        return

    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(active_id)
    if not proxy:
        print(f"Active proxy ID={active_id} not found in library (may have been removed).")
        return

    result = subprocess.run(
        ["systemctl", "is-active", "sing-box"], capture_output=True, text=True
    )
    svc_status = result.stdout.strip()

    bypass = state.get("bypass") or []
    dns = state.get("dns")
    clash_api = state.get("clash_api", False)
    utls = state.get("utls")

    print(f"Active proxy: [{active_id}] {proxy['tag']}")
    print(f"Protocol:     {proxy['protocol']}")
    print(f"Host:         {proxy['host']}:{proxy['port']}")
    print(f"Mode:         {state.get('mode', 'socks')}")
    print(f"Bypass:       {','.join(bypass) if bypass else 'off'}")
    print(f"DNS:          {dns if dns else 'default'}")
    print(f"Clash API:    {'on (:9090)' if clash_api else 'off'}")
    print(f"uTLS:         {utls if utls else 'off'}")
    print(f"sing-box:     {svc_status}")
    print(f"System proxy: {'on' if state.get('sysproxy') else 'off'}")
    print(f"HTTP proxy:   http://127.0.0.1:7890")
    print(f"SOCKS5 proxy: socks5://127.0.0.1:7891")


def _check_not_tun(cmd: str):
    """Print error and exit if current mode is TUN."""
    state = load_state()
    if state.get("mode") == "tun":
        print(
            f"Error: '{cmd}' is not available in TUN mode — all traffic is routed through "
            "the proxy, making direct TCP tests meaningless and temp sing-box probes loop.\n"
            "Run 'proxyctl tun off' first, run your tests, then re-enable TUN.",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_test(args):
    _check_not_tun("test")
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(args.id)
    if not proxy:
        print(f"Error: proxy {args.id} not found.", file=sys.stderr)
        sys.exit(1)
    host = proxy["host"]
    port = proxy["port"]
    print(f"Testing [{args.id}] {proxy['tag']} → {host}:{port} ...", end=" ", flush=True)
    latency = tcp_test(host, port, args.timeout)
    if latency is not None:
        print(f"OK  {latency:.0f}ms")
    else:
        print("FAIL")
        sys.exit(1)


def cmd_test_all(args):
    _check_not_tun("test-all")
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxies = lib.all()
    if not proxies:
        print("No proxies in library.")
        return
    print(f"{'ID':>4}  {'Protocol':<14}  {'Country':<4}  {'Host':<38}  {'Port'}  Result")
    print("─" * 90)
    for id_, proxy in proxies:
        latency = tcp_test(proxy["host"], proxy["port"], args.timeout)
        result = f"OK  {latency:.0f}ms" if latency is not None else "FAIL"
        print(
            f"{id_:>4}  {proxy['protocol']:<14}  {proxy.get('country') or '??':<4}  "
            f"{proxy['host']:<38}  {proxy['port']:<6}  {result}"
        )


def cmd_probe_all(args):
    _check_not_tun("probe-all")
    import queue as _queue

    lib = ProxyLibrary(PROXIES_FILE).load()
    proxies = lib.all()
    if not proxies:
        print("No proxies in library.")
        return

    state = load_state()
    active_id = state.get("active_id")
    utls = state.get("utls")
    timeout = args.timeout
    total = len(proxies)

    port_pool = _queue.Queue()
    for i in range(PROBE_BULK_CONCURRENCY):
        port_pool.put(PROBE_TEMP_PORT_BASE + i)

    done_count = [0]
    results: dict = {}
    lock = threading.Lock()

    def _probe_one(pid, entry):
        outbound = entry.get("outbound", {})
        if pid == active_id:
            ok, msg, ms = http_probe(
                f"http://127.0.0.1:{PROBE_ACTIVE_PORT}", timeout=timeout
            )
        else:
            p = port_pool.get()
            try:
                ok, msg, ms = _probe_via_temp_singbox(
                    outbound, utls=utls, timeout=timeout, port=p
                )
            finally:
                port_pool.put(p)
        sym = "✓" if ok else "✗"
        with lock:
            done_count[0] += 1
            results[pid] = ok
            tag = entry.get("tag", "")[:30]
            print(f"[{done_count[0]:>3}/{total}] {sym} #{pid:<4} {tag:<30}  {msg}")

    threads = [
        threading.Thread(target=_probe_one, args=(pid, entry), daemon=True)
        for pid, entry in proxies
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lib2 = ProxyLibrary(PROXIES_FILE).load()
    for pid, ok in results.items():
        e = lib2.get(pid)
        if e is not None:
            e["live"] = ok
    lib2.save()

    ok_count = sum(1 for v in results.values() if v)
    print(f"\n{ok_count}/{total} proxies live")


def cmd_test_active(args):
    state = load_state()
    active_id = state.get("active_id")
    if active_id is None:
        print("No active proxy. Use 'proxyctl use <id>' first.", file=sys.stderr)
        sys.exit(1)

    proxy_url = f"http://127.0.0.1:{PROBE_ACTIVE_PORT}"
    print(f"Probing via {proxy_url} ...")
    ok, msg, _ = http_probe(proxy_url, timeout=args.timeout)
    lib = ProxyLibrary(PROXIES_FILE).load()
    lib.set_live(active_id, ok)
    if ok:
        print(f"OK — {msg}")
    else:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


def _parse_id_args(raw_ids: list) -> list:
    """Parse id arguments supporting ranges like '1-5' → [1,2,3,4,5]."""
    result = []
    for arg in raw_ids:
        s = str(arg)
        if "-" in s:
            parts = s.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid id or range: {arg!r}")
            result.extend(range(lo, hi + 1))
        else:
            try:
                result.append(int(s))
            except ValueError:
                raise ValueError(f"Invalid id: {arg!r}")
    return result


def cmd_remove(args):
    lib = ProxyLibrary(PROXIES_FILE).load()
    state = load_state()
    active_id = state.get("active_id")

    to_remove: list = []

    if getattr(args, "all", False):
        to_remove = [id_ for id_, _ in lib.all()]
    elif getattr(args, "protocol", None):
        to_remove = [id_ for id_, v in lib.all() if v["protocol"] == args.protocol]
    elif getattr(args, "country", None):
        to_remove = [id_ for id_, v in lib.all() if v["country"] == args.country.upper()]
    else:
        try:
            to_remove = _parse_id_args(args.ids)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    removed = 0
    for id_ in to_remove:
        if lib.remove(id_):
            removed += 1
            if id_ == active_id:
                print(f"Warning: removed active proxy [{id_}] — stopping sing-box.")
                service_action("stop")
                save_state({"active_id": None, "mode": "socks"})
        else:
            print(f"Warning: proxy {id_} not found.", file=sys.stderr)

    lib.save()
    print(f"Removed {removed} proxy(ies).")


def cmd_tun(args):
    state = load_state()
    if state.get("active_id") is None:
        print("No active proxy. Use 'proxyctl use <id>' first.", file=sys.stderr)
        sys.exit(1)

    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(state["active_id"])
    if not proxy:
        print("Active proxy not found in library.", file=sys.stderr)
        sys.exit(1)

    new_mode = "tun" if args.action == "on" else "socks"
    config = generate_active_config(
        proxy["outbound"],
        mode=new_mode,
        bypass=state.get("bypass") or [],
        dns=state.get("dns"),
        clash_api=state.get("clash_api", False),
        utls=state.get("utls"),
    )
    SING_BOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = SING_BOX_CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    os.replace(tmp, SING_BOX_CONFIG)
    state["mode"] = new_mode
    save_state(state)
    service_action("restart")
    print(f"TUN mode {'enabled' if args.action == 'on' else 'disabled'}.")


def _write_service_unit():
    SING_BOX_SERVICE_PATH.write_text(SING_BOX_UNIT.format(bin=SING_BOX_BIN))
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "sing-box"], check=True)
    print(f"Service file written: {SING_BOX_SERVICE_PATH}")
    print("Ordering: After=network-online.target  Before=docker.service cloudflared.service")


def cmd_service_update(args):
    if not Path(SING_BOX_BIN).exists():
        print(f"Error: {SING_BOX_BIN} not found — run 'proxyctl install' first.", file=sys.stderr)
        sys.exit(1)
    _write_service_unit()
    print("sing-box service updated. Changes take effect on next boot (or 'proxyctl restart').")


def cmd_install(args):
    import tarfile as _tarfile
    import tempfile

    print("Fetching latest sing-box release from GitHub...")
    api_url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    with urllib.request.urlopen(api_url) as resp:
        release = json.loads(resp.read())

    asset = next(
        (a for a in release["assets"]
         if "linux-amd64" in a["name"] and a["name"].endswith(".tar.gz")),
        None,
    )
    if not asset:
        print("Error: could not find linux-amd64 release asset.", file=sys.stderr)
        sys.exit(1)

    print(f"Downloading {asset['name']}...")
    with tempfile.TemporaryDirectory() as tmpdir:
        archive = os.path.join(tmpdir, asset["name"])
        urllib.request.urlretrieve(asset["browser_download_url"], archive)

        with _tarfile.open(archive) as tf:
            member = next(
                m for m in tf.getmembers()
                if m.name.endswith("/sing-box") or m.name == "sing-box"
            )
            member.name = "sing-box"
            tf.extract(member, tmpdir, filter="data")

        subprocess.run(
            ["install", "-m", "755", os.path.join(tmpdir, "sing-box"), SING_BOX_BIN],
            check=True,
        )

    print(f"Installed: {SING_BOX_BIN}")

    Path("/etc/sing-box").mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    _write_service_unit()
    print("sing-box service installed and enabled.")
    print("Run: proxyctl add <file.txt> to load proxies.")


# ── TUI ──────────────────────────────────────────────────────────────────────

def _wcswidth(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in s)


def _wcstrunc(s: str, max_w: int) -> str:
    w, out = 0, []
    for c in s:
        cw = 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
        if w + cw > max_w:
            break
        out.append(c)
        w += cw
    return ''.join(out)


def _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies, status_msg, marked_ids):
    import curses
    try:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        active_id = state.get("active_id")

        try:
            r = subprocess.run(["systemctl", "is-active", "sing-box"],
                               capture_output=True, text=True, timeout=1)
            svc = r.stdout.strip()
        except Exception:
            svc = "?"

        mark_info = f"  |  {len(marked_ids)} marked" if marked_ids else ""
        header = (f" proxyctl  |  sing-box: {svc}  |  mode: {state.get('mode','socks')}"
                  f"  |  {len(proxies)} proxies{mark_info}")
        stdscr.addstr(0, 0, _wcstrunc(header, w - 1), curses.A_BOLD)
        stdscr.addstr(1, 0, "─" * (w - 1))

        list_h = h - 4
        id_w, proto_w, country_w, lat_w, live_w, host_w = 5, 8, 4, 6, 2, 23
        tag_w = max(8, w - id_w - proto_w - country_w - lat_w - live_w - host_w - 13)

        for i, (pid, entry) in enumerate(proxies[scroll_off:scroll_off + list_h]):
            row = 2 + i
            is_active = pid == active_id
            is_sel = (scroll_off + i) == selected
            is_marked = pid in marked_ids

            cursor = "▶" if is_sel else " "
            check  = "*" if is_marked else " "
            active = "●" if is_active else " "
            proto = (entry.get("protocol") or "?")[:proto_w]
            country = (entry.get("country") or "--")[:country_w]
            tag = _wcstrunc(entry.get("tag", ""), tag_w)
            host = f"{entry.get('host','')}:{entry.get('port','')}".ljust(host_w)[:host_w]
            live_val = entry.get("live")
            live_sym = "✓" if live_val is True else "✗" if live_val is False else "·"
            live_color = 1 if live_val is True else 3 if live_val is False else 0
            lat = latencies.get(pid)
            if isinstance(lat, str):       # testing in progress: "…2s"
                lat_str = lat.rjust(lat_w)
                lat_color = 0
            elif lat is False:             # tested, unreachable
                lat_str = "FAIL".rjust(lat_w)
                lat_color = 3
            elif lat is not None:          # tested, reachable
                lat_str = f"{lat:.0f}ms".rjust(lat_w)
                lat_color = 0
            else:                          # not tested yet
                lat_str = "---".rjust(lat_w)
                lat_color = 0

            prefix = _wcstrunc(
                f"{cursor}{check}{active} {pid:>{id_w}}  {proto:<{proto_w}} {country:<{country_w}}  "
                f"{tag:<{tag_w}}  {host} ", w - lat_w - live_w - 1)
            line = (prefix + lat_str + " " + live_sym)[:w - 1].ljust(w - 1)

            attr = curses.A_REVERSE if is_sel else curses.A_NORMAL
            if is_marked and curses.has_colors():
                attr |= curses.color_pair(2)
            elif is_active and curses.has_colors():
                attr |= curses.color_pair(1)
            try:
                stdscr.addstr(row, 0, line, attr)
                if not is_sel and curses.has_colors():
                    lat_col = max(0, min(w - lat_w - live_w - 1, len(prefix)))
                    if lat_color:
                        stdscr.addstr(row, lat_col, lat_str, curses.color_pair(lat_color))
                    live_col = lat_col + lat_w + 1
                    if live_col < w - 1:
                        stdscr.addstr(row, live_col, live_sym,
                                      curses.color_pair(live_color) if live_color else curses.A_DIM)
            except curses.error:
                pass

        stdscr.addstr(h - 2, 0, "─" * (w - 1))
        if status_msg:
            footer = status_msg
        elif marked_ids:
            footer = f" [{len(marked_ids)} marked]  Space: toggle  D: delete marked  Esc: clear  Q: quit"
        else:
            footer = " ↑↓/jk: nav  Spc: mark  U: use  T: lat  A: lat-all  p: probe  B: probe-all  D: del  F: del FAIL  Q: quit"
        try:
            stdscr.addstr(h - 1, 0, _wcstrunc(footer, w - 1))
        except curses.error:
            pass

        stdscr.refresh()
    except curses.error:
        pass


def _tui_suspend(stdscr, fn, *args, **kwargs):
    """Leave curses, run fn(), show output, wait for Enter, return to curses."""
    import curses
    curses.endwin()
    print()
    try:
        fn(*args, **kwargs)
    except SystemExit:
        pass
    except Exception as e:
        print(f"Error: {e}")
    try:
        input("\nPress Enter to return to menu...")
    except (EOFError, KeyboardInterrupt):
        pass
    stdscr.refresh()


def _tui_main(stdscr):
    import curses
    curses.curs_set(0)
    curses.noecho()
    stdscr.keypad(True)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)

    state = load_state()
    proxies = ProxyLibrary(PROXIES_FILE).load().all()
    latencies: dict = {}
    marked_ids: set = set()
    status_msg = ""
    selected = 0

    active_id = state.get("active_id")
    for i, (pid, _) in enumerate(proxies):
        if pid == active_id:
            selected = i
            break

    scroll_off = 0
    if curses.has_colors():
        curses.init_pair(2, curses.COLOR_YELLOW, -1)

    while True:
        h, _ = stdscr.getmaxyx()
        list_h = h - 4

        if selected < scroll_off:
            scroll_off = selected
        elif selected >= scroll_off + list_h:
            scroll_off = selected - list_h + 1

        _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies, status_msg, marked_ids)
        status_msg = ""

        key = stdscr.getch()

        if not proxies:
            if key in (ord('q'), ord('Q'), 27):
                break
            continue

        if key in (curses.KEY_UP, ord('k'), ord('K')):
            selected = max(0, selected - 1)

        elif key in (curses.KEY_DOWN, ord('j'), ord('J')):
            selected = min(len(proxies) - 1, selected + 1)

        elif key == curses.KEY_PPAGE:
            selected = max(0, selected - list_h)

        elif key == curses.KEY_NPAGE:
            selected = min(len(proxies) - 1, selected + list_h)

        elif key == ord(' '):
            pid, _ = proxies[selected]
            if pid in marked_ids:
                marked_ids.discard(pid)
            else:
                marked_ids.add(pid)
            # auto-advance cursor
            selected = min(len(proxies) - 1, selected + 1)

        elif key == 27:  # Esc — clear marks or quit
            if marked_ids:
                marked_ids.clear()
                status_msg = " Selection cleared"
            else:
                break

        elif key in (ord('u'), ord('U'), 10, 13):
            pid, entry = proxies[selected]
            ns = argparse.Namespace(
                id=pid, mode=state.get("mode", "socks"),
                bypass=None, dns=None, clash_api=None, utls=None,
            )
            _tui_suspend(stdscr, cmd_use, ns)
            state = load_state()
            proxies = ProxyLibrary(PROXIES_FILE).load().all()
            status_msg = f" ● Active: [{pid}] {_wcstrunc(entry.get('tag',''), 40)}"

        elif key in (ord('t'), ord('T')):
            if state.get("mode") == "tun":
                status_msg = " T/A unavailable in TUN mode — all traffic is routed through the proxy"
                continue
            pid, entry = proxies[selected]
            host, port = entry.get("host", ""), entry.get("port", 0)

            result: list = [None]
            done = threading.Event()

            def _run_test():
                result[0] = tcp_test(host, port, timeout=5.0)
                done.set()

            threading.Thread(target=_run_test, daemon=True).start()

            t_start = time.time()
            stdscr.timeout(200)
            while not done.is_set():
                elapsed = time.time() - t_start
                latencies[pid] = f"…{elapsed:.0f}s"
                _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies,
                          f" Testing [{pid}]...", marked_ids)
                stdscr.getch()
            stdscr.timeout(-1)

            lat = result[0]
            latencies[pid] = lat if lat is not None else False
            status_msg = f" [{pid}] {'%.0fms' % lat if lat is not None else 'FAIL — unreachable'}"

        elif key in (ord('d'), ord('D')):
            to_delete = list(marked_ids) if marked_ids else [proxies[selected][0]]
            n = len(to_delete)
            h2, w2 = stdscr.getmaxyx()
            if n == 1:
                msg = f" Delete [{to_delete[0]}]? Press D to confirm, any other key to cancel"
            else:
                msg = f" Delete {n} marked proxies? Press D to confirm, any other key to cancel"
            try:
                stdscr.addstr(h2 - 1, 0, _wcstrunc(msg, w2 - 1), curses.A_REVERSE)
            except curses.error:
                pass
            stdscr.refresh()
            c2 = stdscr.getch()
            if c2 in (ord('d'), ord('D')):
                lib = ProxyLibrary(PROXIES_FILE).load()
                removed = 0
                stopped = False
                for pid in to_delete:
                    if lib.remove(pid):
                        removed += 1
                        latencies.pop(pid, None)
                        if state.get("active_id") == pid and not stopped:
                            service_action("stop", silent=True)
                            stopped = True
                lib.save()
                if stopped:
                    state = load_state()
                marked_ids.clear()
                proxies = lib.all()
                selected = min(selected, max(0, len(proxies) - 1))
                status_msg = f" Deleted {removed} proxy(ies)"
            else:
                status_msg = " Cancelled"

        elif key == ord('p'):
            state = load_state()
            sel_pid, sel_entry = proxies[selected]
            active_id = state.get("active_id")
            is_active_sel = sel_pid == active_id

            if is_active_sel and active_id is None:
                status_msg = " No active proxy — use U/Enter to activate one first"
            elif is_active_sel:
                proxy_url = f"http://127.0.0.1:{PROBE_ACTIVE_PORT}"
                result: list = [None]
                done = threading.Event()

                def _run_probe_active(url=proxy_url):
                    result[0] = http_probe(url)
                    done.set()

                threading.Thread(target=_run_probe_active, daemon=True).start()

                t_start = time.time()
                stdscr.timeout(200)
                while not done.is_set():
                    elapsed = time.time() - t_start
                    _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies,
                              f" Probing #{sel_pid} via {proxy_url}... {elapsed:.0f}s", marked_ids)
                    stdscr.getch()
                stdscr.timeout(-1)

                ok, msg, _ = result[0]
                lib = ProxyLibrary(PROXIES_FILE).load()
                lib.set_live(sel_pid, ok)
                proxies = lib.all()
                status_msg = f" ✓ #{sel_pid} {msg}" if ok else f" ✗ #{sel_pid} FAIL: {msg}"
            else:
                proxy_url = f"http://127.0.0.1:{PROBE_TEMP_PORT}"
                result2: list = [None]
                done2 = threading.Event()
                _utls = state.get("utls")

                def _run_probe_temp(entry=sel_entry["outbound"], utls=_utls, url=proxy_url):
                    result2[0] = _probe_via_temp_singbox(entry, utls=utls)
                    done2.set()

                threading.Thread(target=_run_probe_temp, daemon=True).start()

                t_start = time.time()
                stdscr.timeout(200)
                while not done2.is_set():
                    elapsed = time.time() - t_start
                    _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies,
                              f" Probing #{sel_pid} via {proxy_url} (temp)... {elapsed:.0f}s",
                              marked_ids)
                    stdscr.getch()
                stdscr.timeout(-1)

                ok, msg, _ = result2[0]
                lib = ProxyLibrary(PROXIES_FILE).load()
                lib.set_live(sel_pid, ok)
                proxies = lib.all()
                status_msg = f" ✓ #{sel_pid} {msg}" if ok else f" ✗ #{sel_pid} FAIL: {msg}"

        elif key in (ord('b'), ord('B')):
            if state.get("mode") == "tun":
                status_msg = " B unavailable in TUN mode — temp sing-box processes would loop through the tunnel"
                continue
            import queue as _queue
            total = len(proxies)
            _state = load_state()
            _active_id = _state.get("active_id")
            _utls = _state.get("utls")
            done_count_p = [0]
            count_lock_p = threading.Lock()
            all_done_p = threading.Event()
            live_results: dict = {}

            port_pool = _queue.Queue()
            for _i in range(PROBE_BULK_CONCURRENCY):
                port_pool.put(PROBE_TEMP_PORT_BASE + _i)

            def _probe_http_one(pid, entry):
                outbound = entry.get("outbound", {})
                if pid == _active_id:
                    ok, msg, ms = http_probe(
                        f"http://127.0.0.1:{PROBE_ACTIVE_PORT}",
                        timeout=PROBE_BULK_TIMEOUT,
                    )
                else:
                    p = port_pool.get()
                    try:
                        ok, msg, ms = _probe_via_temp_singbox(
                            outbound, utls=_utls, timeout=PROBE_BULK_TIMEOUT, port=p
                        )
                    finally:
                        port_pool.put(p)
                with count_lock_p:
                    done_count_p[0] += 1
                    live_results[pid] = ok
                    if done_count_p[0] == total:
                        all_done_p.set()

            for pid, entry in proxies:
                threading.Thread(target=_probe_http_one, args=(pid, entry), daemon=True).start()

            stdscr.timeout(200)
            while not all_done_p.is_set():
                _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies,
                          f" HTTP probing all... {done_count_p[0]}/{total}", marked_ids)
                stdscr.getch()
            stdscr.timeout(-1)

            lib = ProxyLibrary(PROXIES_FILE).load()
            for pid, ok in live_results.items():
                e = lib.get(pid)
                if e is not None:
                    e["live"] = ok
            lib.save()
            proxies = lib.all()
            ok_count = sum(1 for v in live_results.values() if v)
            status_msg = f" HTTP probe done: {ok_count}/{total} live"

        elif key in (ord('a'), ord('A')):
            if state.get("mode") == "tun":
                status_msg = " T/A unavailable in TUN mode — all traffic is routed through the proxy"
                continue
            total = len(proxies)
            done_count = [0]
            count_lock = threading.Lock()
            all_done = threading.Event()

            for pid, _ in proxies:
                latencies[pid] = "…"

            def _test_one(pid, entry):
                host, port = entry.get("host", ""), entry.get("port", 0)
                r = tcp_test(host, port, timeout=5.0)
                latencies[pid] = r if r is not None else False
                with count_lock:
                    done_count[0] += 1
                    if done_count[0] == total:
                        all_done.set()

            for pid, entry in proxies:
                threading.Thread(target=_test_one, args=(pid, entry), daemon=True).start()

            stdscr.timeout(200)
            while not all_done.is_set():
                _tui_draw(stdscr, proxies, selected, scroll_off, state, latencies,
                          f" Testing all... {done_count[0]}/{total}", marked_ids)
                stdscr.getch()
            stdscr.timeout(-1)

            fails = sum(1 for pid, _ in proxies if latencies.get(pid) is False)
            status_msg = f" Tested {total} proxies: {fails} failed, {total - fails} ok"

        elif key in (ord('f'), ord('F')):
            fail_ids = [pid for pid, _ in proxies if latencies.get(pid) is False]
            if not fail_ids:
                status_msg = " No failed proxies — run A to test all first"
            else:
                n = len(fail_ids)
                h2, w2 = stdscr.getmaxyx()
                msg = f" Delete {n} FAIL proxy(ies)? Press F to confirm, any other key to cancel"
                try:
                    stdscr.addstr(h2 - 1, 0, _wcstrunc(msg, w2 - 1), curses.A_REVERSE)
                except curses.error:
                    pass
                stdscr.refresh()
                c2 = stdscr.getch()
                if c2 in (ord('f'), ord('F')):
                    lib = ProxyLibrary(PROXIES_FILE).load()
                    removed = 0
                    stopped = False
                    for pid in fail_ids:
                        if lib.remove(pid):
                            removed += 1
                            latencies.pop(pid, None)
                            if state.get("active_id") == pid and not stopped:
                                service_action("stop", silent=True)
                                stopped = True
                    lib.save()
                    if stopped:
                        state = load_state()
                    marked_ids -= set(fail_ids)
                    proxies = lib.all()
                    selected = min(selected, max(0, len(proxies) - 1))
                    status_msg = f" Deleted {removed} FAIL proxy(ies)"
                else:
                    status_msg = " Cancelled"

        elif key in (ord('q'), ord('Q')):
            break


def cmd_tui():
    import curses
    try:
        curses.wrapper(_tui_main)
    except KeyboardInterrupt:
        pass


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) == 1:
        cmd_tui()
        return

    parser = argparse.ArgumentParser(
        prog="proxyctl",
        description="CLI/TUI manager for sing-box proxy on a remote Ubuntu server.",
        epilog=(
            "Run without arguments to open the interactive TUI.\n\n"
            "Quick start:\n"
            "  proxyctl add proxies.txt   # load URIs from file\n"
            "  proxyctl list              # show library\n"
            "  proxyctl use 1             # activate proxy #1\n"
            "  proxyctl status            # show active proxy and settings\n"
            "  proxyctl probe-all         # HTTP-probe all proxies\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    # ── Library ──────────────────────────────────────────────────────────────
    sub.add_parser(
        "compact",
        help="renumber all proxy IDs starting from 1",
        description=(
            "Renumber all proxies in the library starting from 1, eliminating gaps.\n"
            "Updates active_id in state automatically. sing-box is not restarted."
        ),
    )

    p = sub.add_parser(
        "add",
        help="add proxies from a file or a single URI",
        description=(
            "Add proxies from a text file (one URI per line) or a single URI string.\n"
            "Supported protocols: vless://, vmess://, trojan://, ss://, hysteria2://\n"
            "Country is auto-detected from flag emoji in the tag (e.g. 🇩🇪)."
        ),
    )
    p.add_argument(
        "source",
        help="path to a text file with URIs, or a single URI string",
    )

    p = sub.add_parser(
        "list",
        help="list proxies in the library",
        description="Print the proxy library as a table: ID | protocol | country | host | port | live | tag.",
    )
    p.add_argument("--protocol", metavar="PROTO",
                   help="filter by protocol (vless, vmess, trojan, ss, hysteria2)")
    p.add_argument("--country", metavar="CC",
                   help="filter by country code, e.g. RU or DE")

    p = sub.add_parser(
        "show",
        help="show full details of a proxy",
        description="Print all fields of proxy <id>, including the raw URI and full sing-box outbound JSON.",
    )
    p.add_argument("id", type=int, help="proxy ID")

    # ── Activation ───────────────────────────────────────────────────────────
    p = sub.add_parser(
        "use",
        help="activate a proxy (writes config, restarts sing-box)",
        description=(
            "Switch to proxy <id>: generate sing-box config, write it to\n"
            "/etc/sing-box/active.json, restart the service, and enable system proxy.\n\n"
            "All flags (--bypass, --dns, --utls, --clash-api) are persisted in state\n"
            "and inherited by the next 'use' call automatically."
        ),
    )
    p.add_argument("id", type=int, help="proxy ID to activate")
    p.add_argument(
        "--mode", choices=["socks", "tun"], default="socks",
        help="proxy mode: socks (HTTP/SOCKS5 on ports 7890-7892) or tun (transparent, requires root). Default: socks",
    )
    p.add_argument(
        "--bypass", default=None, metavar="CC[,CC]",
        help=(
            "Comma-separated country codes whose traffic goes direct (e.g. ru,cn).\n"
            "Uses SagerNet geoip+geosite rule-sets updated daily by sing-box.\n"
            "'off' to disable bypass routing."
        ),
    )
    p.add_argument(
        "--dns", default=None, metavar="ADDR",
        help=(
            "DNS server for sing-box to use. Formats:\n"
            "  8.8.8.8              plain UDP\n"
            "  8.8.8.8:5353         UDP on custom port\n"
            "  tls://1.1.1.1        DNS-over-TLS (DoT)\n"
            "  https://dns.google/dns-query  DNS-over-HTTPS (DoH)\n"
            "'off' to remove custom DNS (use system resolver). Default: tls://1.1.1.1"
        ),
    )
    p.add_argument(
        "--utls", default=None, metavar="FP",
        help=(
            "uTLS fingerprint — makes TLS ClientHello look like a real browser.\n"
            "Values: chrome, firefox, safari, random, off.\n"
            "Especially important for proxies behind Cloudflare Workers / CDN frontends.\n"
            "If the URI already contains fp=<value>, that takes precedence.\n"
            "Default: chrome"
        ),
    )
    p.add_argument(
        "--clash-api", dest="clash_api", choices=["on", "off"], default=None,
        help="enable (on) or disable (off) Clash-compatible REST API on 127.0.0.1:9090",
    )

    sub.add_parser(
        "status",
        help="show active proxy and current settings",
        description="Print the active proxy ID, tag, sing-box service state, mode, DNS, uTLS, bypass, and proxy ports.",
    )

    # ── Testing ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "test",
        help="TCP latency to a proxy server",
        description="Measure TCP connect time to the proxy server's host:port. Does not go through the proxy.",
    )
    p.add_argument("id", type=int, help="proxy ID")
    p.add_argument("--timeout", type=float, default=5.0, metavar="SEC",
                   help="connect timeout in seconds (default: 5)")

    p = sub.add_parser(
        "test-all",
        help="TCP latency to all proxies",
        description="Measure TCP connect time to all proxy servers in parallel and print a table.",
    )
    p.add_argument("--timeout", type=float, default=5.0, metavar="SEC",
                   help="connect timeout per proxy in seconds (default: 5)")

    p = sub.add_parser(
        "test-active",
        help="HTTP probe through the active proxy",
        description=(
            "Send an HTTP request through the running sing-box instance (port 7890).\n"
            "Step 1: connectivity check via connectivitycheck.gstatic.com.\n"
            "Step 2: IP/country/ISP lookup via ip-api.com.\n"
            "Saves ✓/✗ live status to the active proxy in the library."
        ),
    )
    p.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="HTTP request timeout in seconds (default: 10)")

    p = sub.add_parser(
        "probe-all",
        help="HTTP probe all proxies in parallel",
        description=(
            "HTTP-probe every proxy in the library simultaneously (up to 8 at a time).\n"
            "Active proxy is tested through port 7890. All others spin up a temporary\n"
            "sing-box process on ports 17900-17907, run the probe, then terminate.\n"
            "Saves ✓/✗ live status for each proxy. Results printed as they arrive."
        ),
    )
    p.add_argument("--timeout", type=float, default=PROBE_BULK_TIMEOUT, metavar="SEC",
                   help=f"HTTP request timeout per proxy in seconds (default: {PROBE_BULK_TIMEOUT:.0f})")

    # ── Library management ───────────────────────────────────────────────────
    p = sub.add_parser(
        "remove",
        help="remove proxies from the library",
        description=(
            "Remove one or more proxies by ID. Supports individual IDs, ranges, and filters.\n"
            "If the removed proxy is active, sing-box is stopped."
        ),
    )
    p.add_argument("ids", nargs="*",
                   help="IDs to remove: individual (3), ranges (1-5), or mixed (1-5 8 10)")
    p.add_argument("--all", action="store_true",
                   help="remove all proxies from the library")
    p.add_argument("--protocol", metavar="PROTO",
                   help="remove all proxies with this protocol (e.g. vmess)")
    p.add_argument("--country", metavar="CC",
                   help="remove all proxies with this country code (e.g. RU)")

    # ── Service ──────────────────────────────────────────────────────────────
    sub.add_parser("start",   help="start the sing-box systemd service")
    sub.add_parser("stop",    help="stop sing-box and disable system proxy")
    sub.add_parser("restart", help="restart the sing-box systemd service")
    sub.add_parser("logs",    help="show last 50 lines of sing-box journal logs")

    p = sub.add_parser(
        "tun",
        help="enable or disable TUN (transparent proxy) mode",
        description=(
            "Switch between TUN and SOCKS modes.\n"
            "TUN mode routes all system traffic transparently — requires root."
        ),
    )
    p.add_argument("action", choices=["on", "off"], help="on: enable TUN, off: disable")

    p = sub.add_parser(
        "sysproxy",
        help="manage system proxy settings (GNOME + /etc/environment)",
        description=(
            "Configure system-wide HTTP/SOCKS5 proxy.\n"
            "  on:     set GNOME gsettings + /etc/environment to 127.0.0.1:7890\n"
            "  off:    clear both\n"
            "  status: show current state of both mechanisms"
        ),
    )
    p.add_argument("action", choices=["on", "off", "status"])

    sub.add_parser(
        "install",
        help="download sing-box binary and install systemd service",
        description=(
            "Download the latest sing-box release from GitHub, install it to\n"
            "/usr/local/bin/sing-box, and create + enable a systemd service unit."
        ),
    )
    sub.add_parser(
        "service-update",
        help="rewrite systemd service file (After=network-online, Before=docker/cloudflared)",
        description=(
            "Overwrite /etc/systemd/system/sing-box.service with the current template\n"
            "and reload systemd. Does not restart sing-box or re-download the binary.\n\n"
            "Use this after 'proxyctl install' to apply the latest service unit without\n"
            "reinstalling, or whenever docker/cloudflared ordering needs to be refreshed."
        ),
    )

    args = parser.parse_args()
    dispatch = {
        "compact": cmd_compact,
        "add": cmd_add, "list": cmd_list, "show": cmd_show,
        "use": cmd_use, "status": cmd_status,
        "test": cmd_test, "test-all": cmd_test_all, "test-active": cmd_test_active,
        "probe-all": cmd_probe_all,
        "remove": cmd_remove,
        "start":   lambda a: service_action("start"),
        "stop":    cmd_stop,
        "restart": lambda a: service_action("restart"),
        "logs": cmd_logs, "tun": cmd_tun, "sysproxy": cmd_sysproxy,
        "install": cmd_install, "service-update": cmd_service_update,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
