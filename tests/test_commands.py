import json
import shutil
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from conftest import VLESS_REALITY, SS_B64, TROJAN, HYSTERIA2
import proxyctl
from proxyctl import ProxyLibrary, load_state, save_state, parse_uri, build_library_entry, _parse_id_args


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


# ── list / show ──────────────────────────────────────────────────────────────

def test_list_all(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_list(_make_args(protocol=None, country=None))
    out = capsys.readouterr().out
    assert "vless" in out
    assert "ss" in out or "shadowsocks" in out


def test_list_filter_protocol(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_list(_make_args(protocol="vless", country=None))
    out = capsys.readouterr().out
    assert "vless" in out
    assert "trojan" not in out


def test_list_filter_country(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_list(_make_args(protocol=None, country="RU"))
    out = capsys.readouterr().out
    assert "RU" in out


def test_list_empty(tmp_library, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    proxyctl.cmd_list(_make_args(protocol=None, country=None))
    out = capsys.readouterr().out
    assert "No proxies" in out


def test_show_existing(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    proxyctl.cmd_show(_make_args(id=1))
    out = capsys.readouterr().out
    assert "vless" in out
    assert "fastcon-tgg.harknmav.fun" in out


def test_show_nonexistent_exits(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    with pytest.raises(SystemExit):
        proxyctl.cmd_show(_make_args(id=999))


# ── service / use / status ────────────────────────────────────────────────────

def test_service_action_calls_sudo_first():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        proxyctl.service_action("start")
        mock_run.assert_called_once_with(
            ["sudo", "-n", "systemctl", "start", "sing-box"], capture_output=True, text=True
        )


def test_service_action_falls_back_to_systemctl():
    # sudo -n fails (returncode=1) → should retry with plain systemctl
    results = [MagicMock(returncode=1, stderr=""), MagicMock(returncode=0)]
    with patch("subprocess.run", side_effect=results) as mock_run:
        proxyctl.service_action("start")
        assert mock_run.call_count == 2
        mock_run.assert_called_with(
            ["systemctl", "start", "sing-box"], capture_output=True, text=True
        )


def test_service_action_exits_on_failure(capsys):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="Unit not found")
        with pytest.raises(SystemExit):
            proxyctl.service_action("start")


def test_use_writes_config_and_restarts(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch)
    config_path = tmp_path / "active.json"
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", config_path)

    with patch("proxyctl.service_action") as mock_sa, \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        proxyctl.cmd_use(_make_args(id=1, mode="socks", bypass=None, dns=None, clash_api=None, utls=None))

    assert config_path.exists()
    cfg = json.loads(config_path.read_text())
    assert cfg["route"]["final"] is not None
    mock_sa.assert_called_with("restart", silent=True)


def test_use_tun_mode_config(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch)
    config_path = tmp_path / "active.json"
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", config_path)

    with patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        proxyctl.cmd_use(_make_args(id=1, mode="tun", bypass=None, dns=None, clash_api=None, utls=None))

    cfg = json.loads(config_path.read_text())
    inbound_types = [i["type"] for i in cfg["inbounds"]]
    assert "tun" in inbound_types


def test_use_nonexistent_id_exits(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    with pytest.raises(SystemExit):
        proxyctl.cmd_use(_make_args(id=999, mode="socks", bypass=None, dns=None, clash_api=None, utls=None))


def test_use_prints_log_on_start_failure(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch)
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")

    with patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="failed\n", returncode=1)
        with pytest.raises(SystemExit):
            proxyctl.cmd_use(_make_args(id=1, mode="socks", bypass=None, dns=None, clash_api=None, utls=None))


def test_status_no_active(tmp_library, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    proxyctl.cmd_status(_make_args())
    out = capsys.readouterr().out
    assert "No active" in out or "none" in out.lower()


def test_status_with_active(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    save_state({"active_id": 1, "mode": "socks"})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        proxyctl.cmd_status(_make_args())
    out = capsys.readouterr().out
    assert "vless" in out or "1" in out


# ── tcp_test / test commands ──────────────────────────────────────────────────

def test_tcp_test_success():
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value = MagicMock()
        result = proxyctl.tcp_test("1.2.3.4", 443, timeout=2.0)
    assert result is not None
    assert result >= 0


def test_tcp_test_failure():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        result = proxyctl.tcp_test("1.2.3.4", 443, timeout=2.0)
    assert result is None


def test_cmd_test_ok(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    with patch("proxyctl.tcp_test", return_value=42.0):
        proxyctl.cmd_test(_make_args(id=1, timeout=5.0))
    out = capsys.readouterr().out
    assert "OK" in out
    assert "42" in out


def test_cmd_test_fail_exits(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch)
    with patch("proxyctl.tcp_test", return_value=None):
        with pytest.raises(SystemExit):
            proxyctl.cmd_test(_make_args(id=1, timeout=5.0))


def test_cmd_test_all_output(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    with patch("proxyctl.tcp_test", side_effect=[10.0, None, 20.0]):
        proxyctl.cmd_test_all(_make_args(timeout=5.0))
    out = capsys.readouterr().out
    assert "OK" in out
    assert "FAIL" in out


def test_cmd_test_active_ok(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    save_state({"active_id": 1, "mode": "socks"})
    with patch("proxyctl.http_probe", return_value=(True, "1.2.3.4 | Russia | TestISP | 42ms", 42.0)):
        proxyctl.cmd_test_active(_make_args(timeout=10.0))
    out = capsys.readouterr().out
    assert "OK" in out
    assert "1.2.3.4" in out


def test_cmd_test_active_no_active(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    with pytest.raises(SystemExit):
        proxyctl.cmd_test_active(_make_args(timeout=10.0))


# ── tun ──────────────────────────────────────────────────────────────────────

def test_tun_on(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch)
    save_state({"active_id": 1, "mode": "socks"})
    config_path = tmp_path / "active.json"
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", config_path)

    with patch("proxyctl.service_action") as mock_sa:
        proxyctl.cmd_tun(_make_args(action="on"))

    cfg = json.loads(config_path.read_text())
    inbound_types = [i["type"] for i in cfg["inbounds"]]
    assert "tun" in inbound_types
    assert load_state()["mode"] == "tun"
    mock_sa.assert_called_with("restart")


def test_tun_off(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch)
    save_state({"active_id": 1, "mode": "tun"})
    config_path = tmp_path / "active.json"
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", config_path)

    with patch("proxyctl.service_action"):
        proxyctl.cmd_tun(_make_args(action="off"))

    cfg = json.loads(config_path.read_text())
    inbound_types = [i["type"] for i in cfg["inbounds"]]
    assert "tun" not in inbound_types
    assert load_state()["mode"] == "socks"


def test_tun_no_active_exits(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    with pytest.raises(SystemExit):
        proxyctl.cmd_tun(_make_args(action="on"))


# ── _parse_id_args ───────────────────────────────────────────────────────────

def test_parse_id_args_plain():
    assert _parse_id_args(["1", "3", "5"]) == [1, 3, 5]

def test_parse_id_args_range():
    assert _parse_id_args(["1-5"]) == [1, 2, 3, 4, 5]

def test_parse_id_args_mixed():
    assert _parse_id_args(["1", "3-5", "8"]) == [1, 3, 4, 5, 8]

def test_parse_id_args_single_range():
    assert _parse_id_args(["7-7"]) == [7]

def test_parse_id_args_invalid():
    with pytest.raises(ValueError):
        _parse_id_args(["abc"])

def test_parse_id_args_invalid_range():
    with pytest.raises(ValueError):
        _parse_id_args(["1-x"])


def test_cmd_remove_range(tmp_library, monkeypatch, capsys):
    _populated_lib(tmp_library, monkeypatch)
    # Add a second and third proxy
    lib = ProxyLibrary(tmp_library).load()
    from conftest import VLESS_REALITY
    from proxyctl import parse_uri, build_library_entry
    for _ in range(3):
        entry = build_library_entry(VLESS_REALITY, parse_uri(VLESS_REALITY))
        lib.add(entry)
    lib.save()

    with patch("proxyctl.service_action"):
        proxyctl.cmd_remove(_make_args(ids=["1-3"], all=False, protocol=None, country=None))

    out = capsys.readouterr().out
    assert "Removed 3" in out


# ── sysproxy ─────────────────────────────────────────────────────────────────

def test_set_env_proxy_on(tmp_library, monkeypatch, tmp_path):
    env_file = tmp_path / "environment"
    env_file.write_text("LANG=en_US.UTF-8\n")
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_path / "state.json")
    with patch("proxyctl.Path") as mock_path_cls:
        # Only intercept /etc/environment; let other Path calls through
        real_path = Path
        def path_side_effect(arg=""):
            p = real_path(arg) if arg else real_path()
            if str(arg) == "/etc/environment":
                return env_file
            return p
        mock_path_cls.side_effect = path_side_effect
        with patch("proxyctl._set_gnome_proxy", return_value=False):
            proxyctl._set_env_proxy(True)

    content = env_file.read_text()
    assert "http_proxy=http://127.0.0.1:7890" in content
    assert "HTTPS_PROXY=http://127.0.0.1:7890" in content
    assert "no_proxy=" in content
    assert "LANG=en_US.UTF-8" in content


def test_set_env_proxy_off_removes_vars(tmp_path):
    env_file = tmp_path / "environment"
    env_file.write_text(
        "LANG=en_US.UTF-8\n"
        "http_proxy=http://127.0.0.1:7890\n"
        "HTTP_PROXY=http://127.0.0.1:7890\n"
        "https_proxy=http://127.0.0.1:7890\n"
        "HTTPS_PROXY=http://127.0.0.1:7890\n"
        "no_proxy=localhost,127.0.0.1,::1\n"
        "NO_PROXY=localhost,127.0.0.1,::1\n"
    )
    with patch("proxyctl.Path") as mock_path_cls:
        real_path = Path
        def path_side_effect(arg=""):
            p = real_path(arg) if arg else real_path()
            if str(arg) == "/etc/environment":
                return env_file
            return p
        mock_path_cls.side_effect = path_side_effect
        proxyctl._set_env_proxy(False)

    content = env_file.read_text()
    assert "http_proxy" not in content
    assert "HTTPS_PROXY" not in content
    assert "LANG=en_US.UTF-8" in content


def test_cmd_sysproxy_on(tmp_library, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    with patch("proxyctl._set_gnome_proxy", return_value=True) as mock_gnome, \
         patch("proxyctl._set_env_proxy", return_value=True) as mock_env:
        proxyctl.cmd_sysproxy(_make_args(action="on"))
    mock_gnome.assert_called_once_with(True)
    mock_env.assert_called_once_with(True)
    out = capsys.readouterr().out
    assert "on" in out
    state = load_state()
    assert state.get("sysproxy") is True


def test_cmd_sysproxy_off(tmp_library, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    save_state({"active_id": None, "mode": "socks", "sysproxy": True})
    with patch("proxyctl._set_gnome_proxy", return_value=True), \
         patch("proxyctl._set_env_proxy", return_value=True):
        proxyctl.cmd_sysproxy(_make_args(action="off"))
    assert load_state().get("sysproxy") is False
    out = capsys.readouterr().out
    assert "off" in out


def test_cmd_stop_disables_sysproxy(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    save_state({"active_id": 1, "mode": "socks", "sysproxy": True})
    with patch("proxyctl.service_action") as mock_sa, \
         patch("proxyctl._set_gnome_proxy", return_value=True), \
         patch("proxyctl._set_env_proxy", return_value=True):
        proxyctl.cmd_stop(_make_args())
    mock_sa.assert_called_once_with("stop")
    assert load_state().get("sysproxy") is False


def test_use_enables_sysproxy(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch)
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")
    with patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl._set_gnome_proxy", return_value=True) as mock_gnome, \
         patch("proxyctl._set_env_proxy", return_value=True), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        proxyctl.cmd_use(_make_args(id=1, mode="socks", bypass=None, dns=None, clash_api=None, utls=None))
    mock_gnome.assert_called_once_with(True)


# ── install ──────────────────────────────────────────────────────────────────

def _fake_release_tarball(tmp_path):
    """Build a real .tar.gz containing a fake sing-box binary, mirroring the
    upstream GitHub release layout (binary nested one directory deep)."""
    import tarfile
    src_dir = tmp_path / "archive_src"
    src_dir.mkdir()
    binpath = src_dir / "sing-box"
    binpath.write_bytes(b"#!/bin/sh\necho fake sing-box\n")
    tar_path = tmp_path / "sing-box-1.0.0-linux-amd64.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(binpath, arcname="sing-box-1.0.0-linux-amd64/sing-box")
    return tar_path


def _patch_install_network(tar_path):
    release_json = {
        "assets": [{
            "name": "sing-box-1.0.0-linux-amd64.tar.gz",
            "browser_download_url": "https://example.invalid/sing-box.tar.gz",
        }]
    }

    def _fake_urlopen(url):
        m = MagicMock()
        m.__enter__ = MagicMock(return_value=m)
        m.__exit__ = MagicMock(return_value=False)
        m.read.return_value = json.dumps(release_json).encode()
        return m

    def _fake_urlretrieve(url, dest):
        shutil.copy(tar_path, dest)

    return (
        patch("urllib.request.urlopen", side_effect=_fake_urlopen),
        patch("urllib.request.urlretrieve", side_effect=_fake_urlretrieve),
    )


def test_cmd_install_extracts_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(proxyctl, "CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "etc-sing-box" / "active.json")
    monkeypatch.setattr(proxyctl, "SING_BOX_SERVICE_PATH", tmp_path / "sing-box.service")
    tar_path = _fake_release_tarball(tmp_path)
    p_urlopen, p_urlretrieve = _patch_install_network(tar_path)

    with p_urlopen, p_urlretrieve, patch("subprocess.run") as mock_run:
        proxyctl.cmd_install(_make_args())

    install_calls = [c for c in mock_run.call_args_list if c.args[0][0] == "install"]
    assert install_calls, "expected an 'install' subprocess call to place the sing-box binary"


def test_cmd_install_fixes_config_dir_ownership_under_sudo(tmp_path, monkeypatch):
    """Confirmed live: 'sudo proxyctl install' resolves CONFIG_DIR to the invoking
    user's home via SUDO_USER (correct path), but the mkdir runs as root — the
    directory ends up owned by root, locking the user out of their own config
    without sudo on every later command.
    """
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(proxyctl, "CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "etc-sing-box" / "active.json")
    monkeypatch.setattr(proxyctl, "SING_BOX_SERVICE_PATH", tmp_path / "sing-box.service")
    monkeypatch.setattr(proxyctl.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1234")
    monkeypatch.setenv("SUDO_GID", "1234")
    tar_path = _fake_release_tarball(tmp_path)
    p_urlopen, p_urlretrieve = _patch_install_network(tar_path)

    with p_urlopen, p_urlretrieve, patch("subprocess.run"), \
         patch("os.chown") as mock_chown:
        proxyctl.cmd_install(_make_args())

    mock_chown.assert_any_call(proxyctl.CONFIG_DIR, 1234, 1234)


def test_cmd_install_skips_chown_when_not_root(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(proxyctl, "CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "etc-sing-box" / "active.json")
    monkeypatch.setattr(proxyctl, "SING_BOX_SERVICE_PATH", tmp_path / "sing-box.service")
    monkeypatch.setattr(proxyctl.os, "geteuid", lambda: 1000)
    tar_path = _fake_release_tarball(tmp_path)
    p_urlopen, p_urlretrieve = _patch_install_network(tar_path)

    with p_urlopen, p_urlretrieve, patch("subprocess.run"), \
         patch("os.chown") as mock_chown:
        proxyctl.cmd_install(_make_args())

    mock_chown.assert_not_called()


def test_cmd_install_works_on_python_without_extract_filter_kwarg(tmp_path, monkeypatch):
    """Python < 3.12 doesn't support TarFile.extract(filter=...) (added in 3.12,
    PEP 706) — confirmed live deploying to a Debian 12 / Python 3.11.2 server,
    where cmd_install crashed with 'unexpected keyword argument filter'.
    """
    import tarfile
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(proxyctl, "CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "etc-sing-box" / "active.json")
    monkeypatch.setattr(proxyctl, "SING_BOX_SERVICE_PATH", tmp_path / "sing-box.service")
    tar_path = _fake_release_tarball(tmp_path)
    p_urlopen, p_urlretrieve = _patch_install_network(tar_path)

    real_extract = tarfile.TarFile.extract

    def _extract_pre_312(self, member, path="", set_attrs=True, *, numeric_owner=False, **kwargs):
        if "filter" in kwargs:
            raise TypeError("extract() got an unexpected keyword argument 'filter'")
        return real_extract(self, member, path, set_attrs, numeric_owner=numeric_owner)

    with p_urlopen, p_urlretrieve, patch("subprocess.run") as mock_run, \
         patch.object(tarfile.TarFile, "extract", _extract_pre_312):
        proxyctl.cmd_install(_make_args())  # must not raise TypeError

    install_calls = [c for c in mock_run.call_args_list if c.args[0][0] == "install"]
    assert install_calls
