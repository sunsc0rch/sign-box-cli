from conftest import VLESS_REALITY, SS_B64, HYSTERIA2
from proxyctl import parse_uri, generate_active_config


def _get_inbound_types(config):
    return [i["type"] for i in config["inbounds"]]

def _get_outbound_types(config):
    return [o["type"] for o in config["outbounds"]]


def test_socks_mode_inbounds():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, mode="socks")
    types = _get_inbound_types(cfg)
    assert "http" in types
    assert "socks" in types
    assert "mixed" in types
    assert "tun" not in types


def test_tun_mode_adds_tun_inbound():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, mode="tun")
    types = _get_inbound_types(cfg)
    assert "tun" in types


def test_tun_inbound_fields():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, mode="tun")
    tun = next(i for i in cfg["inbounds"] if i["type"] == "tun")
    assert tun["auto_route"] is True
    assert tun["inet4_address"] == "172.19.0.1/30"


def test_outbounds_contain_proxy_direct_block():
    out = parse_uri(SS_B64)
    cfg = generate_active_config(out)
    types = _get_outbound_types(cfg)
    assert "shadowsocks" in types
    assert "direct" in types
    assert "block" in types


def test_route_final_points_to_proxy_tag():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    assert cfg["route"]["final"] == out["tag"]


def test_http_port():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    http_in = next(i for i in cfg["inbounds"] if i["type"] == "http")
    assert http_in["listen_port"] == 7890


def test_socks_port():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    socks_in = next(i for i in cfg["inbounds"] if i["type"] == "socks")
    assert socks_in["listen_port"] == 7891


def test_mixed_port():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    mixed_in = next(i for i in cfg["inbounds"] if i["type"] == "mixed")
    assert mixed_in["listen_port"] == 7892


def test_hysteria2_config_structure():
    out = parse_uri(HYSTERIA2)
    cfg = generate_active_config(out)
    proxy_out = next(o for o in cfg["outbounds"] if o["type"] == "hysteria2")
    assert proxy_out["password"] == "mypassword"
