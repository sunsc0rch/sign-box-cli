import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from conftest import VLESS_REALITY, SS_B64, TROJAN, HYSTERIA2
import proxyctl
from proxyctl import ProxyLibrary, load_state, save_state, parse_uri, build_library_entry


@pytest.fixture
def lib(tmp_library, monkeypatch):
    """Return a fresh ProxyLibrary instance pointing at tmp files."""
    return ProxyLibrary(tmp_library)


def _make_args(**kw):
    return MagicMock(**kw)


# ── add ──────────────────────────────────────────────────────────────────────

def test_add_from_file(tmp_library, monkeypatch, tmp_path):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    content = "\n".join([VLESS_REALITY, SS_B64, TROJAN, HYSTERIA2, "", "bad-line"])
    f = tmp_path / "proxies.txt"
    f.write_text(content)

    args = _make_args(source=str(f))
    proxyctl.cmd_add(args)

    loaded = ProxyLibrary(tmp_library).load()
    assert len(loaded.all()) == 4


def test_add_single_uri(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    args = _make_args(source=VLESS_REALITY)
    proxyctl.cmd_add(args)

    loaded = ProxyLibrary(tmp_library).load()
    assert len(loaded.all()) == 1
    assert loaded.get(1)["protocol"] == "vless"


def test_add_skips_bad_lines(tmp_library, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    f = tmp_path / "p.txt"
    f.write_text("bad-line\n" + VLESS_REALITY + "\nalso-bad\n")
    proxyctl.cmd_add(_make_args(source=str(f)))
    out = capsys.readouterr().out
    assert "Added 1" in out
    assert "skipped 2" in out


# ── remove ───────────────────────────────────────────────────────────────────

def _populated_lib(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    for uri in [VLESS_REALITY, SS_B64, TROJAN]:
        lib = ProxyLibrary(tmp_library).load()
        out = parse_uri(uri)
        entry = build_library_entry(uri, out)
        lib.add(entry)
        lib.save()


def test_remove_by_id(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_remove(_make_args(ids=[1], all=False, protocol=None, country=None))
    lib = ProxyLibrary(tmp_library).load()
    assert lib.get(1) is None
    assert len(lib.all()) == 2


def test_remove_multiple_ids(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_remove(_make_args(ids=[1, 2], all=False, protocol=None, country=None))
    assert len(ProxyLibrary(tmp_library).load().all()) == 1


def test_remove_all(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_remove(_make_args(ids=[], all=True, protocol=None, country=None))
    assert ProxyLibrary(tmp_library).load().all() == []


def test_remove_by_protocol(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_remove(_make_args(ids=[], all=False, protocol="vless", country=None))
    remaining = ProxyLibrary(tmp_library).load().all()
    assert all(v["protocol"] != "vless" for _, v in remaining)


def test_remove_active_stops_service(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    save_state({"active_id": 1, "mode": "socks"})
    with patch("proxyctl.service_action") as mock_sa:
        proxyctl.cmd_remove(_make_args(ids=[1], all=False, protocol=None, country=None))
        mock_sa.assert_called_once_with("stop")
    out = capsys.readouterr().out
    assert any(word in out.lower() for word in ["warning", "warn", "active", "removing"])
