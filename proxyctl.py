#!/usr/bin/env python3
"""proxyctl - CLI manager for sing-box proxy on Ubuntu server"""

import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

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

def generate_active_config(outbound: dict, mode: str = "socks") -> dict:
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

    return {
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": {"final": outbound["tag"]},
    }


# ── Service Management ───────────────────────────────────────────────────────

def service_action(action: str):
    pass  # Task 10

def cmd_logs(args):
    pass  # Task 10


# ── TCP Test ─────────────────────────────────────────────────────────────────

def tcp_test(host: str, port: int, timeout: float = 5.0) -> Optional[float]:
    pass  # Task 11


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


def cmd_list(args):    pass
def cmd_show(args):    pass
def cmd_use(args):     pass
def cmd_status(args):  pass
def cmd_test(args):    pass
def cmd_test_all(args): pass
def cmd_test_active(args): pass
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
        to_remove = list(args.ids)

    removed = 0
    for id_ in to_remove:
        if id_ == active_id:
            print(f"Warning: removing active proxy [{id_}] — stopping sing-box.")
            service_action("stop")
            save_state({"active_id": None, "mode": "socks"})
        if lib.remove(id_):
            removed += 1
        else:
            print(f"Warning: proxy {id_} not found.", file=sys.stderr)

    lib.save()
    print(f"Removed {removed} proxy(ies).")
def cmd_tun(args):     pass
def cmd_install(args): pass


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(prog="proxyctl", description="Manage sing-box proxies")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add");      p.add_argument("source")
    p = sub.add_parser("list");     p.add_argument("--protocol"); p.add_argument("--country")
    p = sub.add_parser("show");     p.add_argument("id", type=int)
    p = sub.add_parser("use");      p.add_argument("id", type=int); p.add_argument("--mode", choices=["socks","tun"], default="socks")
    sub.add_parser("status")
    p = sub.add_parser("test");     p.add_argument("id", type=int); p.add_argument("--timeout", type=float, default=5.0)
    p = sub.add_parser("test-all"); p.add_argument("--timeout", type=float, default=5.0)
    p = sub.add_parser("test-active"); p.add_argument("--timeout", type=float, default=10.0)
    p = sub.add_parser("remove");   p.add_argument("ids", nargs="*", type=int); p.add_argument("--all", action="store_true"); p.add_argument("--protocol"); p.add_argument("--country")
    sub.add_parser("start"); sub.add_parser("stop"); sub.add_parser("restart"); sub.add_parser("logs")
    p = sub.add_parser("tun");      p.add_argument("action", choices=["on","off"])
    sub.add_parser("install")

    args = parser.parse_args()
    dispatch = {
        "add": cmd_add, "list": cmd_list, "show": cmd_show,
        "use": cmd_use, "status": cmd_status,
        "test": cmd_test, "test-all": cmd_test_all, "test-active": cmd_test_active,
        "remove": cmd_remove,
        "start":   lambda a: service_action("start"),
        "stop":    lambda a: service_action("stop"),
        "restart": lambda a: service_action("restart"),
        "logs": cmd_logs, "tun": cmd_tun, "install": cmd_install,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
