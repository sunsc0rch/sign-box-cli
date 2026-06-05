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
    assert tun["address"] == ["172.19.0.1/30"]
    assert "sniff" not in tun  # moved to route rule action in sing-box 1.13
    # private subnets and proxy server IP excluded from TUN
    exclude = tun.get("route_exclude_address", [])
    assert "10.0.0.0/8" in exclude
    assert "192.168.0.0/16" in exclude
    server = out.get("server", "")
    assert f"{server}/32" in exclude


def test_tun_mode_sniff_route_rule():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, mode="tun")
    assert "rules" in cfg["route"]
    assert {"action": "sniff"} in cfg["route"]["rules"]


def test_socks_mode_no_sniff_rule():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, mode="socks")
    # socks mode has no sniff rule and no route rules by default
    assert "rules" not in cfg["route"]


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


def test_bypass_adds_route_rules_and_rule_sets():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, bypass=["ru"])
    assert "rules" in cfg["route"]
    assert "rule_set" in cfg["route"]
    rule_set_tags = [rs["tag"] for rs in cfg["route"]["rule_set"]]
    assert "geoip-ru" in rule_set_tags
    assert "geosite-ru" in rule_set_tags
    # Private IP rule is first
    assert cfg["route"]["rules"][0] == {"ip_is_private": True, "outbound": "direct"}
    # RU bypass rule is second
    ru_rule = cfg["route"]["rules"][1]
    assert ru_rule["outbound"] == "direct"
    assert "geoip-ru" in ru_rule["rule_set"]
    assert "geosite-ru" in ru_rule["rule_set"]


def test_bypass_multi_country():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, bypass=["ru", "cn"])
    rule_set_tags = [rs["tag"] for rs in cfg["route"]["rule_set"]]
    assert "geoip-ru" in rule_set_tags
    assert "geoip-cn" in rule_set_tags
    assert len(cfg["route"]["rules"]) == 3  # private + ru + cn


def test_no_bypass_no_route_rules():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    assert "rules" not in cfg["route"]
    assert "rule_set" not in cfg["route"]


def test_dns_adds_dns_section():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, dns="8.8.8.8")
    assert "dns" in cfg
    srv = cfg["dns"]["servers"][0]
    assert srv["tag"] == "dns-main"
    assert srv["type"] == "udp"
    assert srv["server"] == "8.8.8.8"
    assert cfg["dns"]["final"] == "dns-main"


def test_dns_tls_format():
    from proxyctl import _build_dns_server
    s = _build_dns_server("tls://1.1.1.1")
    assert s == {"tag": "dns-main", "type": "tls", "server": "1.1.1.1"}


def test_dns_https_format():
    from proxyctl import _build_dns_server
    s = _build_dns_server("https://dns.google/dns-query")
    assert s["type"] == "https"
    assert s["server"] == "dns.google"
    assert s["path"] == "/dns-query"


def test_dns_plain_ip_with_port():
    from proxyctl import _build_dns_server
    s = _build_dns_server("8.8.8.8:5353")
    assert s["type"] == "udp"
    assert s["server"] == "8.8.8.8"
    assert s["server_port"] == 5353


def test_no_dns_no_dns_section():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    assert "dns" not in cfg


def test_clash_api_adds_experimental():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, clash_api=True)
    assert "experimental" in cfg
    assert cfg["experimental"]["clash_api"]["external_controller"] == "127.0.0.1:9090"


def test_no_clash_api_no_experimental():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out)
    assert "experimental" not in cfg


def test_utls_injects_fingerprint():
    out = parse_uri(VLESS_REALITY)
    cfg = generate_active_config(out, utls="chrome")
    proxy_out = next(o for o in cfg["outbounds"] if o["type"] == "vless")
    assert proxy_out["tls"]["utls"]["fingerprint"] == "chrome"
    assert proxy_out["packet_encoding"] == "xudp"


def test_utls_does_not_override_existing_fp():
    out = parse_uri(VLESS_REALITY)
    out["tls"]["utls"] = {"enabled": True, "fingerprint": "firefox"}
    cfg = generate_active_config(out, utls="chrome")
    proxy_out = next(o for o in cfg["outbounds"] if o["type"] == "vless")
    assert proxy_out["tls"]["utls"]["fingerprint"] == "firefox"


def test_no_utls_no_fingerprint():
    # HYSTERIA2 has TLS but no fp in URI
    out = parse_uri(HYSTERIA2)
    cfg = generate_active_config(out)
    proxy_out = next(o for o in cfg["outbounds"] if o["type"] == "hysteria2")
    assert "utls" not in proxy_out.get("tls", {})
