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


def cmd_use(args):
    lib = ProxyLibrary(PROXIES_FILE).load()
    proxy = lib.get(args.id)
    if not proxy:
        print(f"Error: proxy {args.id} not found.", file=sys.stderr)
        sys.exit(1)

    config = generate_active_config(proxy["outbound"], mode=args.mode)
    SING_BOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = SING_BOX_CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    os.replace(tmp, SING_BOX_CONFIG)
    save_state({"active_id": args.id, "mode": args.mode})

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

    print(
        f"Active: [{args.id}] {proxy['tag']} | {proxy['protocol']} "
        f"| {proxy['host']}:{proxy['port']} | mode={args.mode}"
    )


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

    print(f"Active proxy: [{active_id}] {proxy['tag']}")
    print(f"Protocol:     {proxy['protocol']}")
    print(f"Host:         {proxy['host']}:{proxy['port']}")
    print(f"Mode:         {state.get('mode', 'socks')}")
    print(f"sing-box:     {svc_status}")
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

    proxy_url = "socks5://127.0.0.1:7891"
    test_url = "http://ip-api.com/json"
    try:
        resp = requests.get(
            test_url,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=args.timeout,
        )
        data = resp.json()
        print(
            f"OK — IP: {data.get('query', '?')} | "
            f"Country: {data.get('country', '?')} | "
            f"ISP: {data.get('isp', '?')}"
        )
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)


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
    config = generate_active_config(proxy["outbound"], mode=new_mode)
    SING_BOX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = SING_BOX_CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    os.replace(tmp, SING_BOX_CONFIG)
    save_state({"active_id": state["active_id"], "mode": new_mode})
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
