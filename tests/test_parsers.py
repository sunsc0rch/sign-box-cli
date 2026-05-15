import base64
import json as _json
import pytest
from conftest import VLESS_REALITY, VLESS_WS, VLESS_TLS_TCP, SS_B64, TROJAN, HYSTERIA2
from proxyctl import parse_vless, parse_vmess, parse_ss, parse_trojan, parse_hysteria2, extract_country


def test_vless_reality_basic_fields():
    out = parse_vless(VLESS_REALITY)
    assert out["type"] == "vless"
    assert out["server"] == "fastcon-tgg.harknmav.fun"
    assert out["server_port"] == 443
    assert out["uuid"] == "50b95deb-6394-46c5-b88a-583e5b3ca7ee"
    assert out["flow"] == "xtls-rprx-vision"


def test_vless_reality_tls_block():
    out = parse_vless(VLESS_REALITY)
    tls = out["tls"]
    assert tls["enabled"] is True
    assert tls["server_name"] == "ads.x5.ru"
    assert tls["utls"] == {"enabled": True, "fingerprint": "chrome"}
    assert tls["reality"]["enabled"] is True
    assert tls["reality"]["public_key"] == "PGccrEdFmBaB1rQFJqM-a9jJ1pFsxhUP2sD9KTw5Oz4"
    assert tls["reality"]["short_id"] == "f69d7af2d5fc5e0c"


def test_vless_reality_no_transport_key():
    out = parse_vless(VLESS_REALITY)
    assert "transport" not in out


def test_vless_ws_transport():
    out = parse_vless(VLESS_WS)
    assert out["transport"]["type"] == "ws"
    assert out["transport"]["path"] == "/fp=chrome"
    assert out["transport"]["headers"]["Host"] == "gogo.wknm.dpdns.org"


def test_vless_ws_tls():
    out = parse_vless(VLESS_WS)
    assert out["tls"]["enabled"] is True
    assert out["tls"]["server_name"] == "gogo.wknm.dpdns.org"
    assert "reality" not in out["tls"]


def test_vless_tls_tcp_insecure():
    out = parse_vless(VLESS_TLS_TCP)
    assert out["tls"]["insecure"] is True
    assert "reality" not in out["tls"]


def test_vless_tag_from_fragment():
    out = parse_vless(VLESS_REALITY)
    assert "RUS" in out["tag"]


def test_vless_grpc_transport():
    uri = (
        "vless://uuid@host:443?type=grpc&serviceName=my-service"
        "&security=tls&sni=host#grpc-test"
    )
    out = parse_vless(uri)
    assert out["transport"]["type"] == "grpc"
    assert out["transport"]["service_name"] == "my-service"


def test_vless_grpc_no_service_name():
    uri = "vless://uuid@host:443?type=grpc&security=tls&sni=host#grpc-empty"
    out = parse_vless(uri)
    assert out["transport"]["type"] == "grpc"
    assert "service_name" not in out["transport"]



def _make_vmess(overrides: dict) -> str:
    data = {
        "v": "2", "ps": "vmess-test", "add": "1.2.3.4", "port": "443",
        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aid": "0",
        "scy": "auto", "net": "ws", "type": "none",
        "host": "example.com", "path": "/ws", "tls": "tls", "sni": "example.com",
    }
    data.update(overrides)
    return "vmess://" + base64.b64encode(_json.dumps(data).encode()).decode()


def test_vmess_basic_fields():
    out = parse_vmess(_make_vmess({}))
    assert out["type"] == "vmess"
    assert out["server"] == "1.2.3.4"
    assert out["server_port"] == 443
    assert out["uuid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert out["security"] == "auto"
    assert out["alter_id"] == 0


def test_vmess_ws_transport():
    out = parse_vmess(_make_vmess({"net": "ws", "path": "/proxy", "host": "cdn.example.com"}))
    assert out["transport"]["type"] == "ws"
    assert out["transport"]["path"] == "/proxy"
    assert out["transport"]["headers"]["Host"] == "cdn.example.com"


def test_vmess_tls():
    out = parse_vmess(_make_vmess({"tls": "tls", "sni": "example.com"}))
    assert out["tls"]["enabled"] is True
    assert out["tls"]["server_name"] == "example.com"


def test_vmess_no_tls():
    out = parse_vmess(_make_vmess({"tls": ""}))
    assert "tls" not in out


def test_vmess_tcp_no_transport():
    out = parse_vmess(_make_vmess({"net": "tcp"}))
    assert "transport" not in out


def test_vmess_tag_from_ps():
    out = parse_vmess(_make_vmess({"ps": "my-vmess-proxy"}))
    assert out["tag"] == "my-vmess-proxy"


# ── Shadowsocks tests ────────────────────────────────────────────────────────

def test_ss_base64_at_format():
    # ss://BASE64@host:port  where BASE64 = method:password
    out = parse_ss(SS_B64)
    assert out["type"] == "shadowsocks"
    assert out["server"] == "83.166.250.6"
    assert out["server_port"] == 51287
    assert out["method"] == "chacha20-ietf-poly1305"
    assert out["password"] == "usOjAQXmyRqcY8aRAVFghnyRR"


def test_ss_plain_format():
    # ss://method:password@host:port#tag
    uri = "ss://chacha20-ietf-poly1305:hunter2@10.0.0.1:8388#plain-ss"
    out = parse_ss(uri)
    assert out["method"] == "chacha20-ietf-poly1305"
    assert out["password"] == "hunter2"
    assert out["server"] == "10.0.0.1"
    assert out["server_port"] == 8388


def test_ss_tag():
    out = parse_ss(SS_B64)
    assert out["tag"] == "SS_test"


def test_ss_no_fragment_fallback_tag():
    uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@10.0.0.1:8388"
    # No fragment → tag should be "ss-10.0.0.1"
    out = parse_ss(uri)
    assert out["tag"] == "ss-10.0.0.1"


# ── Trojan tests ─────────────────────────────────────────────────────────────

def test_trojan_basic():
    out = parse_trojan(TROJAN)
    assert out["type"] == "trojan"
    assert out["server"] == "1.2.3.4"
    assert out["server_port"] == 443
    assert out["password"] == "mypassword"


def test_trojan_tls():
    out = parse_trojan(TROJAN)
    assert out["tls"]["enabled"] is True
    assert out["tls"]["server_name"] == "example.com"
    assert out["tls"]["insecure"] is True


def test_trojan_tag():
    out = parse_trojan(TROJAN)
    assert out["tag"] == "trojan-test"


def test_trojan_ws_transport():
    uri = "trojan://pass@host:443?type=ws&path=/ws&host=cdn.example.com&sni=cdn.example.com#t"
    out = parse_trojan(uri)
    assert out["transport"]["type"] == "ws"
    assert out["transport"]["path"] == "/ws"
    assert out["transport"]["headers"]["Host"] == "cdn.example.com"


def test_trojan_tls_always_present():
    uri = "trojan://pass@1.2.3.4:443#minimal"
    out = parse_trojan(uri)
    assert "tls" in out
    assert out["tls"]["enabled"] is True
    assert "insecure" not in out["tls"]


# ── Hysteria2 tests ──────────────────────────────────────────────────────────

def test_hysteria2_basic():
    out = parse_hysteria2(HYSTERIA2)
    assert out["type"] == "hysteria2"
    assert out["server"] == "1.2.3.4"
    assert out["server_port"] == 443
    assert out["password"] == "mypassword"


def test_hysteria2_tls():
    out = parse_hysteria2(HYSTERIA2)
    assert out["tls"]["enabled"] is True
    assert out["tls"]["server_name"] == "example.com"
    assert out["tls"]["insecure"] is True


def test_hysteria2_tag():
    out = parse_hysteria2(HYSTERIA2)
    assert out["tag"] == "hy2-test"


def test_hysteria2_hy2_alias():
    uri = "hy2://pass@host:443?insecure=1#hy2-alias"
    out = parse_hysteria2(uri)
    assert out["type"] == "hysteria2"


def test_hysteria2_tls_always_present():
    uri = "hysteria2://pass@1.2.3.4:443#minimal"
    out = parse_hysteria2(uri)
    assert "tls" in out
    assert out["tls"]["enabled"] is True
    assert "insecure" not in out["tls"]


# ── extract_country tests ────────────────────────────────────────────────────

def test_extract_country_russian_flag():
    assert extract_country("⬜ \U0001f1f7\U0001f1fa RUS ⭐") == "RU"


def test_extract_country_turkish_flag():
    assert extract_country("\U0001f1f9\U0001f1f7 TUR") == "TR"


def test_extract_country_singapore_flag():
    assert extract_country("\U0001f1f8\U0001f1ec SG node") == "SG"


def test_extract_country_no_flag():
    assert extract_country("some proxy without flag") == ""
