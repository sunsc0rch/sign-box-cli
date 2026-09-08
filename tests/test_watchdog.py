import json
import os
import threading
import time
import pytest
from unittest.mock import patch, MagicMock

import proxyctl
from proxyctl import ProxyLibrary, parse_uri, build_library_entry

VLESS_A = (
    "vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@144.31.2.33:443"
    "?alpn=h2&encryption=none&flow=xtls-rprx-vision&security=tls"
    "&sni=pl3.moritech.net&type=tcp&fp=chrome#POL-A"
)
VLESS_B = (
    "vless://55ed97fc-77d1-4802-baf3-acef70776331@31.76.119.117:443"
    "?encryption=none&flow=xtls-rprx-vision"
    "&pbk=lHCkAu_DOVFtE-iL2JGrPt44QeTCFijXuRfuGaSni3Q&security=reality"
    "&sid=9e4eced6e98ed4d4&sni=de.orpheous.ru&type=tcp&fp=chrome#DEU-B"
)
VLESS_C = (
    "vless://55ed97fc-77d1-4802-baf3-acef70776331@31.76.119.117:443"
    "?encryption=none&flow=xtls-rprx-vision"
    "&pbk=lHCkAu_DOVFtE-iL2JGrPt44QeTCFijXuRfuGaSni3Q&security=reality"
    "&sid=9e4eced6e98ed4d4&sni=de.orpheous.ru&type=tcp&fp=firefox#DEU-C"
)


def _populated_lib(tmp_library, monkeypatch, uris, live=None):
    """Load uris into the library (in order, ids 1..N). live: optional list of bool/None per id."""
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    lib = ProxyLibrary(tmp_library).load()
    for uri in uris:
        out = parse_uri(uri)
        entry = build_library_entry(uri, out)
        lib.add(entry)
    lib.save()
    if live:
        lib2 = ProxyLibrary(tmp_library).load()
        for pid, v in zip([e[0] for e in lib2.all()], live):
            if v is not None:
                lib2.get(pid)["live"] = v
        lib2.save()
    return lib


def _make_args(**kw):
    return MagicMock(**kw)


# ── _switch_active ──────────────────────────────────────────────────────────

def test_switch_active_writes_config_no_output(tmp_library, monkeypatch, tmp_path, capsys):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    config_path = tmp_path / "active.json"
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", config_path)

    with patch("proxyctl.service_action") as mock_sa, \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy") as mock_sysproxy, \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        state = proxyctl.load_state()
        ok, reason, proxy = proxyctl._switch_active(1, "socks", None, None, False, None, state)

    assert ok is True
    assert reason == "ok"
    assert proxy["protocol"] == "vless"
    assert config_path.exists()
    mock_sa.assert_called_with("restart", silent=True)
    mock_sysproxy.assert_called_with(True, silent=True)
    assert capsys.readouterr().out == ""


def test_switch_active_no_output_through_real_service_action_and_sysproxy(
    tmp_library, monkeypatch, tmp_path, capsys
):
    """Exercise the real service_action/set_sysproxy code paths (only their outer
    subprocess/filesystem calls are mocked) — the 'no output' contract must hold
    end-to-end, not just when the printing functions themselves are mocked away.
    """
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")

    with patch("subprocess.run") as mock_run, \
         patch("proxyctl._set_gnome_proxy", return_value=True), \
         patch("proxyctl._set_env_proxy", return_value=True), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        state = proxyctl.load_state()
        ok, reason, proxy = proxyctl._switch_active(1, "socks", None, None, False, None, state)

    assert ok is True
    assert capsys.readouterr().out == ""


def test_switch_active_not_found(tmp_library, monkeypatch, tmp_path):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")
    state = proxyctl.load_state()

    ok, reason, msg = proxyctl._switch_active(999, "socks", None, None, False, None, state)

    assert ok is False
    assert reason == "not_found"


def test_switch_active_start_failure_no_output(tmp_library, monkeypatch, tmp_path, capsys):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")

    with patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="failed\n", returncode=1)
        state = proxyctl.load_state()
        ok, reason, msg = proxyctl._switch_active(1, "socks", None, None, False, None, state)

    assert ok is False
    assert reason == "start_failed"
    assert capsys.readouterr().out == ""


# ── cmd_use still works after refactor (regression) ─────────────────────────

def test_cmd_use_still_prints_summary_on_success(tmp_library, monkeypatch, tmp_path, capsys):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")

    with patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        proxyctl.cmd_use(_make_args(id=1, mode="socks", bypass=None, dns=None, clash_api=None, utls=None))

    out = capsys.readouterr().out
    assert "Active: [1]" in out


def test_cmd_use_nonexistent_id_exits(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    with pytest.raises(SystemExit):
        proxyctl.cmd_use(_make_args(id=999, mode="socks", bypass=None, dns=None, clash_api=None, utls=None))


# ── _pick_failover_candidate ────────────────────────────────────────────────

def test_pick_candidate_skips_non_live(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B, VLESS_C],
                   live=[True, None, True])
    lib = ProxyLibrary(tmp_library).load()

    with patch("proxyctl._probe_via_temp_singbox", return_value=(True, "ok", 10.0)) as mock_probe:
        result = proxyctl._pick_failover_candidate(lib, exclude_id=1, utls=None)

    assert result is not None
    pid, entry = result
    assert pid == 3  # id 2 has live=None, skipped
    mock_probe.assert_called_once()


def test_pick_candidate_excludes_active_id(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B], live=[True, True])
    lib = ProxyLibrary(tmp_library).load()

    with patch("proxyctl._probe_via_temp_singbox", return_value=(True, "ok", 10.0)):
        result = proxyctl._pick_failover_candidate(lib, exclude_id=1, utls=None)

    assert result[0] == 2


def test_pick_candidate_skips_failed_reprobe(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B, VLESS_C],
                   live=[True, True, True])
    lib = ProxyLibrary(tmp_library).load()

    # id 1 excluded (active), id 2 fails live reprobe, id 3 passes
    with patch("proxyctl._probe_via_temp_singbox", side_effect=[(False, "fail", 0.0), (True, "ok", 5.0)]):
        result = proxyctl._pick_failover_candidate(lib, exclude_id=1, utls=None)

    assert result[0] == 3


def test_pick_candidate_returns_none_when_no_candidates(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A], live=[True])
    lib = ProxyLibrary(tmp_library).load()

    result = proxyctl._pick_failover_candidate(lib, exclude_id=1, utls=None)

    assert result is None


def test_pick_candidate_uses_dedicated_watchdog_port(tmp_library, monkeypatch):
    """Must not reuse PROBE_TEMP_PORT (17890, the 'p'/'T' TUI keys) or the
    PROBE_TEMP_PORT_BASE pool (17900-17907, 'B'/probe-all) — a collision would make
    a manual probe and a background failover scan fight over the same port and
    spuriously fail a perfectly live candidate.
    """
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B], live=[True, True])
    lib = ProxyLibrary(tmp_library).load()

    with patch("proxyctl._probe_via_temp_singbox", return_value=(True, "ok", 1.0)) as mock_probe:
        proxyctl._pick_failover_candidate(lib, exclude_id=1, utls=None)

    used_port = mock_probe.call_args.kwargs.get("port")
    assert used_port == proxyctl.WATCHDOG_PROBE_PORT
    assert used_port != proxyctl.PROBE_TEMP_PORT
    assert not (proxyctl.PROBE_TEMP_PORT_BASE <= used_port < proxyctl.PROBE_TEMP_PORT_BASE + proxyctl.PROBE_BULK_CONCURRENCY)


def test_pick_candidate_returns_none_when_all_reprobes_fail(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B], live=[True, True])
    lib = ProxyLibrary(tmp_library).load()

    with patch("proxyctl._probe_via_temp_singbox", return_value=(False, "fail", 0.0)):
        result = proxyctl._pick_failover_candidate(lib, exclude_id=1, utls=None)

    assert result is None


# ── _watchdog_check ──────────────────────────────────────────────────────────

def test_watchdog_check_ok_resets_fail_count(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    state = proxyctl.load_state()
    state["active_id"] = 1
    proxyctl.save_state(state)

    with patch("proxyctl.http_probe", return_value=(True, "ok", 5.0)):
        result = proxyctl._watchdog_check(fail_count=2, fail_threshold=3)

    assert result["action"] == "ok"
    assert result["fail_count"] == 0


def test_watchdog_check_fail_below_threshold_does_not_switch(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B], live=[True, True])
    state = proxyctl.load_state()
    state["active_id"] = 1
    proxyctl.save_state(state)

    with patch("proxyctl.http_probe", return_value=(False, "timeout", 0.0)), \
         patch("proxyctl._switch_active") as mock_switch:
        result = proxyctl._watchdog_check(fail_count=1, fail_threshold=3)

    assert result["action"] == "fail_below_threshold"
    assert result["fail_count"] == 2
    mock_switch.assert_not_called()


def test_watchdog_check_no_active_resets_fail_count(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    # no active_id saved -> load_state() defaults to None

    result = proxyctl._watchdog_check(fail_count=2, fail_threshold=3)

    assert result["action"] == "no_active"
    assert result["fail_count"] == 0


def test_watchdog_check_skips_in_tun_mode(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    state = proxyctl.load_state()
    state["active_id"] = 1
    state["mode"] = "tun"
    proxyctl.save_state(state)

    with patch("proxyctl.http_probe") as mock_probe:
        result = proxyctl._watchdog_check(fail_count=2, fail_threshold=3)

    assert result["action"] == "skipped_tun"
    assert result["fail_count"] == 2
    mock_probe.assert_not_called()


def test_watchdog_check_switches_on_threshold_reached(tmp_library, monkeypatch, tmp_path):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B], live=[True, True])
    monkeypatch.setattr(proxyctl, "SING_BOX_CONFIG", tmp_path / "active.json")
    state = proxyctl.load_state()
    state["active_id"] = 1
    state["mode"] = "socks"
    proxyctl.save_state(state)

    with patch("proxyctl.http_probe", return_value=(False, "timeout", 0.0)), \
         patch("proxyctl._probe_via_temp_singbox", return_value=(True, "ok", 5.0)), \
         patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        result = proxyctl._watchdog_check(fail_count=2, fail_threshold=3)

    assert result["action"] == "switched"
    assert result["switched_to"] == 2
    assert result["fail_count"] == 0
    new_state = proxyctl.load_state()
    assert new_state["active_id"] == 2


def test_watchdog_check_stops_when_no_candidates(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    state = proxyctl.load_state()
    state["active_id"] = 1
    proxyctl.save_state(state)

    with patch("proxyctl.http_probe", return_value=(False, "timeout", 0.0)):
        result = proxyctl._watchdog_check(fail_count=2, fail_threshold=3)

    assert result["action"] == "stopped_no_candidates"
    assert result["fail_count"] == 3


# ── lock file ────────────────────────────────────────────────────────────────

def test_lock_prevents_double_acquire(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "watchdog.lock")

    fh1 = proxyctl._watchdog_acquire_lock()
    assert fh1 is not None

    fh2 = proxyctl._watchdog_acquire_lock()
    assert fh2 is None

    proxyctl._watchdog_release_lock(fh1)


def test_lock_losing_attempt_does_not_clobber_winners_pid(tmp_path, monkeypatch):
    """A losing contender must not truncate the lock file — otherwise diagnostics
    (which pid holds the lock) become useless right when they're needed most.
    """
    lock_path = tmp_path / "watchdog.lock"
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", lock_path)

    fh1 = proxyctl._watchdog_acquire_lock()
    assert fh1 is not None
    written_pid = lock_path.read_text()
    assert written_pid == str(os.getpid())

    fh2 = proxyctl._watchdog_acquire_lock()
    assert fh2 is None
    assert lock_path.read_text() == written_pid

    proxyctl._watchdog_release_lock(fh1)


def test_lock_reacquirable_after_release(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "watchdog.lock")

    fh1 = proxyctl._watchdog_acquire_lock()
    proxyctl._watchdog_release_lock(fh1)

    fh2 = proxyctl._watchdog_acquire_lock()
    assert fh2 is not None
    proxyctl._watchdog_release_lock(fh2)


# ── graceful shutdown ────────────────────────────────────────────────────────

def test_watchdog_wait_exits_early_on_stop_event():
    stop_event = threading.Event()

    def _fake_sleep(secs):
        stop_event.set()

    with patch("time.sleep", side_effect=_fake_sleep) as mock_sleep:
        proxyctl._watchdog_wait(7200, stop_event, step=1.0)

    mock_sleep.assert_called_once()


def test_watchdog_wait_full_duration_when_never_stopped():
    stop_event = threading.Event()

    with patch("time.sleep") as mock_sleep:
        proxyctl._watchdog_wait(5.0, stop_event, step=1.0)

    assert mock_sleep.call_count == 5


def test_watchdog_loop_stops_immediately_if_stop_event_preset(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    stop_event = threading.Event()
    stop_event.set()

    with patch("proxyctl._watchdog_check") as mock_check:
        result = proxyctl._watchdog_loop(7200, 3, stop_event=stop_event)

    mock_check.assert_not_called()
    assert result["action"] == "stopped_signal"


def test_watchdog_loop_stops_when_no_candidates_without_waiting(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    stop_event = threading.Event()

    with patch("proxyctl._watchdog_check",
               return_value={"action": "stopped_no_candidates", "fail_count": 3,
                             "message": "no working proxies available", "switched_to": None}), \
         patch("proxyctl._watchdog_wait") as mock_wait, \
         patch("proxyctl._watchdog_record_status"):
        result = proxyctl._watchdog_loop(7200, 3, stop_event=stop_event)

    mock_wait.assert_not_called()
    assert result["action"] == "stopped_no_candidates"


def test_watchdog_loop_waits_between_checks_and_stops_on_signal(tmp_library, monkeypatch):
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    stop_event = threading.Event()
    calls = {"n": 0}

    def _fake_check(fail_count, fail_threshold=3, timeout=15.0):
        calls["n"] += 1
        return {"action": "ok", "fail_count": 0, "message": "ok", "switched_to": None}

    def _fake_wait(interval, ev, step=1.0):
        if calls["n"] >= 2:
            ev.set()

    with patch("proxyctl._watchdog_check", side_effect=_fake_check), \
         patch("proxyctl._watchdog_wait", side_effect=_fake_wait), \
         patch("proxyctl._watchdog_record_status"):
        result = proxyctl._watchdog_loop(7200, 3, stop_event=stop_event)

    assert calls["n"] == 2
    assert result["action"] == "stopped_signal"


# ── CLI: proxyctl watchdog ───────────────────────────────────────────────────

def test_watchdog_run_refuses_when_lock_held(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "watchdog.lock")
    held = proxyctl._watchdog_acquire_lock()
    assert held is not None

    with pytest.raises(SystemExit):
        proxyctl.cmd_watchdog_run(_make_args(interval=7200, fail_threshold=3))

    proxyctl._watchdog_release_lock(held)


def test_watchdog_run_releases_lock_after_loop(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "watchdog.lock")

    with patch("proxyctl._watchdog_loop",
               return_value={"action": "stopped_signal", "fail_count": 0,
                             "message": "stopped", "switched_to": None}), \
         patch("signal.signal"):
        proxyctl.cmd_watchdog_run(_make_args(interval=7200, fail_threshold=3))

    # lock must be free again — a fresh acquire should succeed
    fh = proxyctl._watchdog_acquire_lock()
    assert fh is not None
    proxyctl._watchdog_release_lock(fh)


def test_watchdog_install_writes_unit_and_starts_service(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    (tmp_path / "sing-box").write_text("")  # pretend binary is installed

    with patch("subprocess.run") as mock_run:
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))

    unit_text = (tmp_path / "sing-box-watchdog.service").read_text()
    assert "--interval 7200" in unit_text
    assert "--fail-threshold 3" in unit_text
    called = [c.args[0] for c in mock_run.call_args_list]
    assert ["systemctl", "daemon-reload"] in called
    assert ["systemctl", "enable", "sing-box-watchdog"] in called
    assert ["systemctl", "restart", "sing-box-watchdog"] in called


def test_watchdog_install_bakes_invoking_users_home_into_unit(tmp_path, monkeypatch):
    """The unit runs as User=root, so systemd gives it no HOME — without an explicit
    Environment=HOME=..., _config_home()/Path.home() would resolve to /root and the
    watchdog would read/write a different proxies.json/state.json/lock than the
    interactive user's TUI, silently defeating the whole point of the shared lock.
    """
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    (tmp_path / "sing-box").write_text("")
    fake_home = tmp_path / "home" / "sc0rch"
    monkeypatch.setattr(proxyctl, "_config_home", lambda: fake_home)

    with patch("subprocess.run"):
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))

    unit_text = (tmp_path / "sing-box-watchdog.service").read_text()
    assert f"Environment=HOME={fake_home}" in unit_text


def test_watchdog_unit_does_not_require_singbox_service(tmp_path, monkeypatch):
    """Confirmed live: Requires=sing-box.service makes systemd propagate a stop to
    sing-box-watchdog.service every time the watchdog itself restarts sing-box during
    a failover (service_action("restart") inside _switch_active) — the watchdog kills
    itself mid-switch (SIGKILL after TimeoutStopSec) on every single failover event.
    Ordering via After= is fine; Requires=/BindsTo= must not be used here.
    """
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    (tmp_path / "sing-box").write_text("")

    with patch("subprocess.run"):
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))

    unit_text = (tmp_path / "sing-box-watchdog.service").read_text()
    assert "Requires=" not in unit_text
    assert "BindsTo=" not in unit_text
    assert "After=sing-box.service" in unit_text


def test_watchdog_unit_disables_python_stdout_buffering(tmp_path, monkeypatch):
    """Without this, systemd captures stdout as a non-tty pipe and Python fully
    block-buffers print() — journalctl won't show '[watchdog] ...' lines until the
    buffer fills or the process exits, which for a multi-hour interval can mean a
    day+ of delay. Confirmed live: sys.stdout.line_buffering was False under the
    installed unit and journalctl showed nothing despite state.json recording
    successful checks.
    """
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    (tmp_path / "sing-box").write_text("")

    with patch("subprocess.run"):
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))

    unit_text = (tmp_path / "sing-box-watchdog.service").read_text()
    assert "PYTHONUNBUFFERED=1" in unit_text


def test_watchdog_install_warns_when_no_active_proxy(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_path / "state.json")
    (tmp_path / "sing-box").write_text("")

    with patch("subprocess.run"):
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))

    err = capsys.readouterr().err
    assert "no active proxy" in err.lower()


def test_watchdog_install_restarts_when_already_running(tmp_path, monkeypatch):
    """Confirmed live: 'systemctl start' on an already-active unit is a no-op — a
    second 'proxyctl watchdog install' with new --interval/--fail-threshold rewrites
    the unit file but the already-running process keeps its OLD settings until the
    next reboot/manual restart. Must use 'restart' when the unit is already active.
    """
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    (tmp_path / "sing-box").write_text("")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))

    called = [c.args[0] for c in mock_run.call_args_list]
    assert ["systemctl", "restart", "sing-box-watchdog"] in called
    assert ["systemctl", "start", "sing-box-watchdog"] not in called


def test_watchdog_install_requires_singbox_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "sing-box-watchdog.service")
    monkeypatch.setattr(proxyctl, "SING_BOX_BIN", str(tmp_path / "does-not-exist"))

    with pytest.raises(SystemExit):
        proxyctl.cmd_watchdog_install(_make_args(interval=7200, fail_threshold=3))


def test_watchdog_stop_calls_systemctl(monkeypatch):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        proxyctl.cmd_watchdog_stop(_make_args())

    mock_run.assert_called_with(
        ["systemctl", "stop", "sing-box-watchdog"], capture_output=True, text=True
    )


def test_watchdog_delete_removes_unit_and_lock(tmp_path, monkeypatch):
    unit_path = tmp_path / "sing-box-watchdog.service"
    unit_path.write_text("[Unit]")
    lock_path = tmp_path / "watchdog.lock"
    lock_path.write_text("123")
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", unit_path)
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", lock_path)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        proxyctl.cmd_watchdog_delete(_make_args())

    assert not unit_path.exists()
    assert not lock_path.exists()
    called = [c.args[0] for c in mock_run.call_args_list]
    assert ["systemctl", "stop", "sing-box-watchdog"] in called
    assert ["systemctl", "disable", "sing-box-watchdog"] in called
    assert ["systemctl", "daemon-reload"] in called


def test_watchdog_delete_ok_when_nothing_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_SERVICE_PATH", tmp_path / "missing.service")
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "missing.lock")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        proxyctl.cmd_watchdog_delete(_make_args())  # must not raise


def test_watchdog_status_never_checked(tmp_library, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="inactive\n")
        proxyctl.cmd_watchdog_status(_make_args())

    out = capsys.readouterr().out
    assert "never" in out


def test_watchdog_status_shows_last_check(tmp_library, monkeypatch, capsys):
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", tmp_library)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    state = proxyctl.load_state()
    state["watchdog_last_check"] = 1000.0
    state["watchdog_last_action"] = "ok"
    state["watchdog_last_message"] = "ok"
    proxyctl.save_state(state)

    with patch("subprocess.run") as mock_run, patch("time.time", return_value=1005.0):
        mock_run.return_value = MagicMock(stdout="active\n")
        proxyctl.cmd_watchdog_status(_make_args())

    out = capsys.readouterr().out
    assert "ok" in out
    assert "active" in out


# ── TUI integration helpers ─────────────────────────────────────────────────

def test_tui_start_watchdog_returns_none_when_lock_held(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "watchdog.lock")
    held = proxyctl._watchdog_acquire_lock()

    result = proxyctl._tui_start_watchdog()

    assert result is None
    proxyctl._watchdog_release_lock(held)


def test_tui_start_and_stop_watchdog(tmp_path, monkeypatch):
    monkeypatch.setattr(proxyctl, "WATCHDOG_LOCK_FILE", tmp_path / "watchdog.lock")

    def _fake_loop(interval, fail_threshold, stop_event=None):
        stop_event.wait()
        return {"action": "stopped_signal", "fail_count": 0, "message": "stopped", "switched_to": None}

    with patch("proxyctl._watchdog_loop", side_effect=_fake_loop):
        handle = proxyctl._tui_start_watchdog()
        assert handle is not None
        assert handle["thread"].is_alive()

        proxyctl._tui_stop_watchdog(handle)
        assert not handle["thread"].is_alive()

    fh = proxyctl._watchdog_acquire_lock()
    assert fh is not None
    proxyctl._watchdog_release_lock(fh)


def test_tui_stop_watchdog_none_is_noop():
    proxyctl._tui_stop_watchdog(None)  # must not raise


# ── memory soak test ─────────────────────────────────────────────────────────

def _current_rss_kb():
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("VmRSS not found in /proc/self/status")


# ── concurrent-write safety ──────────────────────────────────────────────────

def test_library_save_serializes_against_concurrent_holder(tmp_library, monkeypatch):
    """proxies.json writes from the TUI main thread and the watchdog thread must not
    interleave. Simulate a holder (standing in for the watchdog mid read-modify-write)
    and confirm ProxyLibrary.save() blocks until it releases, rather than racing ahead.
    """
    _populated_lib(tmp_library, monkeypatch, [VLESS_A])
    lib = ProxyLibrary(tmp_library).load()

    released_at = [None]
    save_started_at = [None]

    def _hold_lock():
        with proxyctl._DATA_LOCK:
            released_at[0] = time.monotonic()
            time.sleep(0.2)

    t = threading.Thread(target=_hold_lock)
    t.start()
    time.sleep(0.05)  # let the holder actually acquire first

    save_started_at[0] = time.monotonic()
    lib.save()
    save_finished_at = time.monotonic()
    t.join()

    assert save_finished_at - save_started_at[0] >= 0.1, (
        "ProxyLibrary.save() did not wait for the concurrent holder — "
        "writes could interleave/corrupt proxies.json"
    )


def test_state_save_serializes_against_concurrent_holder(tmp_library, monkeypatch):
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_library.parent / "state.json")
    state = proxyctl.load_state()

    def _hold_lock():
        with proxyctl._DATA_LOCK:
            time.sleep(0.2)

    t = threading.Thread(target=_hold_lock)
    t.start()
    time.sleep(0.05)

    start = time.monotonic()
    proxyctl.save_state(state)
    elapsed = time.monotonic() - start
    t.join()

    assert elapsed >= 0.1, "save_state() did not wait for the concurrent holder"


def test_watchdog_check_no_memory_growth_over_many_iterations(tmp_library, monkeypatch):
    """Run the watchdog check body (the part a long-lived 'proxyctl watchdog run'
    process repeats every interval) many times and confirm RSS doesn't grow —
    catches leaked threads, unclosed handles, or ever-growing in-memory state.
    """
    _populated_lib(tmp_library, monkeypatch, [VLESS_A, VLESS_B, VLESS_C],
                   live=[True, True, True])
    state = proxyctl.load_state()
    state["active_id"] = 1
    proxyctl.save_state(state)

    call = {"n": 0}

    def _fake_http_probe(url, timeout=15.0):
        call["n"] += 1
        # fail two out of three times, to exercise the fail/threshold/reset paths
        return (call["n"] % 3 == 0, "x", 1.0)

    with patch("proxyctl.http_probe", side_effect=_fake_http_probe), \
         patch("proxyctl._probe_via_temp_singbox", return_value=(True, "ok", 1.0)), \
         patch("proxyctl.service_action"), \
         patch("subprocess.run") as mock_run, \
         patch("proxyctl.set_sysproxy"), \
         patch("time.sleep"):
        mock_run.return_value = MagicMock(stdout="active\n", returncode=0)

        # warm up (import caches, first-call allocations) before the baseline sample
        fail_count = 0
        for _ in range(20):
            result = proxyctl._watchdog_check(fail_count, fail_threshold=3)
            fail_count = result["fail_count"]

        baseline_kb = _current_rss_kb()

        for _ in range(300):
            result = proxyctl._watchdog_check(fail_count, fail_threshold=3)
            fail_count = result["fail_count"]
            # active_id may have "switched" — keep the fixture healthy either way
            state = proxyctl.load_state()
            if state.get("active_id") is None:
                state["active_id"] = 1
                proxyctl.save_state(state)

        final_kb = _current_rss_kb()

    growth_kb = final_kb - baseline_kb
    assert growth_kb < 5000, (
        f"RSS grew by {growth_kb} KiB over 300 watchdog checks "
        f"(baseline={baseline_kb} KiB, final={final_kb} KiB) — possible leak"
    )
