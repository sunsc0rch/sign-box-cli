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

CONFIG_DIR = Path.home() / ".config" / "proxyctl"
PROXIES_FILE = CONFIG_DIR / "proxies.json"
STATE_FILE = CONFIG_DIR / "state.json"
SING_BOX_CONFIG = Path("/etc/sing-box/active.json")
SING_BOX_BIN = "/usr/local/bin/sing-box"


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
        id_ = self._data["next_id"]
        self._data["proxies"][str(id_)] = entry
        self._data["next_id"] += 1
        return id_

    def get(self, id_: int) -> Optional[dict]:
        return self._data["proxies"].get(str(id_))

    def all(self) -> list:
        return [(int(k), v) for k, v in self._data["proxies"].items()]

    def remove(self, id_: int) -> bool:
        key = str(id_)
        if key in self._data["proxies"]:
            del self._data["proxies"][key]
            return True
        return False

    def clear(self):
        self._data["proxies"] = {}


# ── State ────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"active_id": None, "mode": "socks"}


def save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ── Config Generator ─────────────────────────────────────────────────────────

def generate_active_config(
    outbound: dict,
    mode: str = "socks",
    bypass: Optional[list] = None,
    dns: Optional[str] = None,
    clash_api: bool = False,
) -> dict:
    inbounds = [
        {"type": "http",  "tag": "http-in",  "listen": "::", "listen_port": 7890},
        {"type": "socks", "tag": "socks-in", "listen": "::", "listen_port": 7891},
        {"type": "mixed", "tag": "mixed-in", "listen": "::", "listen_port": 7892},
    ]
    if mode == "tun":
        inbounds.append({
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": "172.19.0.1/30",
            "auto_route": True,
            "strict_route": True,
            "sniff": True,
        })

    route: dict = {"final": outbound["tag"]}
    if bypass:
        route_rules = [{"ip_is_private": True, "outbound": "direct"}]
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
        route["rules"] = route_rules
        route["rule_set"] = rule_sets

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
            "servers": [{"tag": "dns-main", "address": dns}],
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

def service_action(action: str):
    result = subprocess.run(
        ["systemctl", action, "sing-box"], capture_output=True, text=True
    )
    if result.returncode != 0:
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


# ── CLI Commands ─────────────────────────────────────────────────────────────

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

    print(f"{'ID':>4}  {'Protocol':<14}  {'Country':<4}  {'Host':<38}  {'Port'}  Tag")
    print("─" * 90)
    for id_, v in proxies:
        print(
            f"{id_:>4}  {v['protocol']:<14}  {v.get('country') or '??':<4}  "
            f"{v['host']:<38}  {v['port']:<6}  {v['tag'][:40]}"
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

    return bypass, dns, clash_api


def cmd_use(args):
    state = load_state()
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(args.id)
    if not proxy:
        print(f"Error: proxy {args.id} not found.", file=sys.stderr)
        sys.exit(1)

    bypass, dns, clash_api = _resolve_use_settings(args, state)

    config = generate_active_config(proxy["outbound"], mode=args.mode,
                                    bypass=bypass, dns=dns, clash_api=clash_api)
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

    print(f"Active proxy: [{active_id}] {proxy['tag']}")
    print(f"Protocol:     {proxy['protocol']}")
    print(f"Host:         {proxy['host']}:{proxy['port']}")
    print(f"Mode:         {state.get('mode', 'socks')}")
    print(f"Bypass:       {','.join(bypass) if bypass else 'off'}")
    print(f"DNS:          {dns if dns else 'default'}")
    print(f"Clash API:    {'on (:9090)' if clash_api else 'off'}")
    print(f"sing-box:     {svc_status}")
    print(f"System proxy: {'on' if state.get('sysproxy') else 'off'}")
    print(f"HTTP proxy:   http://127.0.0.1:7890")
    print(f"SOCKS5 proxy: socks5://127.0.0.1:7891")


def cmd_test(args):
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


def cmd_test_active(args):
    state = load_state()
    if state.get("active_id") is None:
        print("No active proxy. Use 'proxyctl use <id>' first.", file=sys.stderr)
        sys.exit(1)
    if requests is None:
        print("Error: 'requests' library not installed. Run: pip install requests", file=sys.stderr)
        sys.exit(1)

    proxy_url = "http://127.0.0.1:7890"
    test_url = "http://ip-api.com/json"
    try:
        resp = requests.get(
            test_url,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=args.timeout,
        )
        if resp.status_code != 200:
            print(f"FAIL: upstream returned HTTP {resp.status_code}", file=sys.stderr)
            sys.exit(1)
        data = resp.json()
        print(
            f"OK — IP: {data.get('query', '?')} | "
            f"Country: {data.get('country', '?')} | "
            f"ISP: {data.get('isp', '?')}"
        )
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
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
    )
    SING_BOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = SING_BOX_CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    os.replace(tmp, SING_BOX_CONFIG)
    state["mode"] = new_mode
    save_state(state)
    service_action("restart")
    print(f"TUN mode {'enabled' if args.action == 'on' else 'disabled'}.")


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

    unit = (
        "[Unit]\n"
        "Description=sing-box proxy service\n"
        "After=network.target\n\n"
        "[Service]\n"
        f"ExecStart={SING_BOX_BIN} run -c /etc/sing-box/active.json\n"
        "Restart=on-failure\n"
        "RestartSec=3s\n"
        "User=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    Path("/etc/systemd/system/sing-box.service").write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "sing-box"], check=True)
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
        id_w, proto_w, country_w, lat_w, host_w = 5, 8, 4, 6, 23
        tag_w = max(8, w - id_w - proto_w - country_w - lat_w - host_w - 13)

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
                f"{tag:<{tag_w}}  {host} ", w - lat_w - 1)
            line = (prefix + lat_str)[:w - 1].ljust(w - 1)

            attr = curses.A_REVERSE if is_sel else curses.A_NORMAL
            if is_marked and curses.has_colors():
                attr |= curses.color_pair(2)
            elif is_active and curses.has_colors():
                attr |= curses.color_pair(1)
            try:
                stdscr.addstr(row, 0, line, attr)
                if lat_color and curses.has_colors() and not is_sel:
                    col = max(0, min(w - lat_w - 1, len(prefix)))
                    stdscr.addstr(row, col, lat_str, curses.color_pair(lat_color))
            except curses.error:
                pass

        stdscr.addstr(h - 2, 0, "─" * (w - 1))
        if status_msg:
            footer = status_msg
        elif marked_ids:
            footer = f" [{len(marked_ids)} marked]  Space: toggle  D: delete marked  Esc: clear  Q: quit"
        else:
            footer = " ↑↓/jk: nav  Space: mark  U: use  T: test  A: test all  D: del  F: del FAIL  Q: quit"
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
                bypass=None, dns=None, clash_api=None,
            )
            _tui_suspend(stdscr, cmd_use, ns)
            state = load_state()
            proxies = ProxyLibrary(PROXIES_FILE).load().all()
            status_msg = f" ● Active: [{pid}] {_wcstrunc(entry.get('tag',''), 40)}"

        elif key in (ord('t'), ord('T')):
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
                            service_action("stop")
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

        elif key in (ord('a'), ord('A')):
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
                                service_action("stop")
                                stopped = True
                    lib.save()
                    if stopped:
                        state = load_state()
                    marked_ids.discard(*fail_ids) if fail_ids else None
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

    parser = argparse.ArgumentParser(prog="proxyctl", description="Manage sing-box proxies")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add");      p.add_argument("source")
    p = sub.add_parser("list");     p.add_argument("--protocol"); p.add_argument("--country")
    p = sub.add_parser("show");     p.add_argument("id", type=int)
    p = sub.add_parser("use");      p.add_argument("id", type=int); p.add_argument("--mode", choices=["socks","tun"], default="socks"); p.add_argument("--bypass", default=None, metavar="CC", help="Country codes to route direct, comma-separated (e.g. ru,cn). 'off' to disable"); p.add_argument("--dns", default=None, help="DNS server address (e.g. 8.8.8.8 or tls://1.1.1.1). 'off' to disable"); p.add_argument("--clash-api", dest="clash_api", choices=["on","off"], default=None, help="Enable Clash API on :9090")
    sub.add_parser("status")
    p = sub.add_parser("test");     p.add_argument("id", type=int); p.add_argument("--timeout", type=float, default=5.0)
    p = sub.add_parser("test-all"); p.add_argument("--timeout", type=float, default=5.0)
    p = sub.add_parser("test-active"); p.add_argument("--timeout", type=float, default=10.0)
    p = sub.add_parser("remove");   p.add_argument("ids", nargs="*"); p.add_argument("--all", action="store_true"); p.add_argument("--protocol"); p.add_argument("--country")
    sub.add_parser("start"); sub.add_parser("stop"); sub.add_parser("restart"); sub.add_parser("logs")
    p = sub.add_parser("tun");      p.add_argument("action", choices=["on","off"])
    p = sub.add_parser("sysproxy"); p.add_argument("action", choices=["on","off","status"])
    sub.add_parser("install")

    args = parser.parse_args()
    dispatch = {
        "add": cmd_add, "list": cmd_list, "show": cmd_show,
        "use": cmd_use, "status": cmd_status,
        "test": cmd_test, "test-all": cmd_test_all, "test-active": cmd_test_active,
        "remove": cmd_remove,
        "start":   lambda a: service_action("start"),
        "stop":    cmd_stop,
        "restart": lambda a: service_action("restart"),
        "logs": cmd_logs, "tun": cmd_tun, "sysproxy": cmd_sysproxy, "install": cmd_install,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
