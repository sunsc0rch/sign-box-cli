import pytest
from conftest import VLESS_REALITY, SS_B64, TROJAN, HYSTERIA2
import proxyctl
from proxyctl import (
    parse_uri, build_library_entry, ProxyLibrary, load_state, save_state
)


def test_parse_uri_vless():
    out = parse_uri(VLESS_REALITY)
    assert out["type"] == "vless"


def test_parse_uri_ss():
    out = parse_uri(SS_B64)
    assert out["type"] == "shadowsocks"


def test_parse_uri_trojan():
    out = parse_uri(TROJAN)
    assert out["type"] == "trojan"


def test_parse_uri_hysteria2():
    out = parse_uri(HYSTERIA2)
    assert out["type"] == "hysteria2"


def test_parse_uri_unknown_raises():
    with pytest.raises(ValueError, match="Unsupported"):
        parse_uri("unknown://something")


def test_build_library_entry_fields():
    out = parse_uri(VLESS_REALITY)
    entry = build_library_entry(VLESS_REALITY, out)
    assert entry["protocol"] == "vless"
    assert entry["host"] == "fastcon-tgg.harknmav.fun"
    assert entry["port"] == 443
    assert entry["country"] == "RU"
    assert entry["raw_uri"] == VLESS_REALITY
    assert entry["outbound"] is out


def test_library_add_and_get(tmp_library):
    lib = ProxyLibrary(tmp_library).load()
    out = parse_uri(VLESS_REALITY)
    entry = build_library_entry(VLESS_REALITY, out)
    id_ = lib.add(entry)
    lib.save()

    lib2 = ProxyLibrary(tmp_library).load()
    assert lib2.get(id_)["protocol"] == "vless"


def test_library_remove(tmp_library):
    lib = ProxyLibrary(tmp_library).load()
    id_ = lib.add(build_library_entry(VLESS_REALITY, parse_uri(VLESS_REALITY)))
    lib.save()
    assert lib.remove(id_) is True
    lib.save()
    assert ProxyLibrary(tmp_library).load().get(id_) is None


def test_library_remove_nonexistent(tmp_library):
    lib = ProxyLibrary(tmp_library).load()
    assert lib.remove(9999) is False


def test_library_all(tmp_library):
    lib = ProxyLibrary(tmp_library).load()
    lib.add(build_library_entry(VLESS_REALITY, parse_uri(VLESS_REALITY)))
    lib.add(build_library_entry(SS_B64, parse_uri(SS_B64)))
    assert len(lib.all()) == 2


def test_library_clear(tmp_library):
    lib = ProxyLibrary(tmp_library).load()
    lib.add(build_library_entry(VLESS_REALITY, parse_uri(VLESS_REALITY)))
    lib.clear()
    assert lib.all() == []


def test_state_roundtrip(tmp_library):
    save_state({"active_id": 3, "mode": "tun"})
    s = load_state()
    assert s["active_id"] == 3
    assert s["mode"] == "tun"


def test_state_defaults_when_missing(tmp_library):
    s = load_state()
    assert s["active_id"] is None
    assert s["mode"] == "socks"
