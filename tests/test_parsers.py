import pytest
from conftest import VLESS_REALITY, VLESS_WS, VLESS_TLS_TCP
from proxyctl import parse_vless


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
