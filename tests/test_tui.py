import proxyctl


# ── _wrap_footer_hints ──────────────────────────────────────────────────────

def test_wrap_hints_fits_on_one_line_when_width_is_generous():
    hints = ["Q: quit", "U: use"]
    lines = proxyctl._wrap_footer_hints(hints, 80)
    assert len(lines) == 1
    assert "Q: quit" in lines[0]
    assert "U: use" in lines[0]


def test_wrap_hints_breaks_into_multiple_lines_when_narrow():
    hints = ["↑↓/jk: nav", "Spc: mark", "U: use", "T: lat", "A: lat-all",
             "p: probe", "B: probe-all", "D: del", "F: del FAIL", "Q: quit"]
    lines = proxyctl._wrap_footer_hints(hints, 30)
    assert len(lines) > 1
    for line in lines:
        assert len(line) <= 30 or proxyctl._wcswidth(line) <= 30


def test_wrap_hints_never_splits_a_single_hint_across_lines():
    hints = ["↑↓/jk: nav", "Spc: mark", "U: use", "T: lat", "A: lat-all",
             "p: probe", "B: probe-all", "D: del", "F: del FAIL", "Q: quit"]
    lines = proxyctl._wrap_footer_hints(hints, 25)
    joined = " ".join(lines)
    for hint in hints:
        assert hint in joined


def test_wrap_hints_respects_width_per_line():
    hints = ["↑↓/jk: nav", "Spc: mark", "U: use", "T: lat", "A: lat-all",
             "p: probe", "B: probe-all", "D: del", "F: del FAIL", "Q: quit"]
    width = 25
    lines = proxyctl._wrap_footer_hints(hints, width)
    for line in lines:
        assert proxyctl._wcswidth(line) <= width


def test_wrap_hints_empty_list_returns_single_empty_line():
    assert proxyctl._wrap_footer_hints([], 40) == [""]


# ── _tui_footer_lines ────────────────────────────────────────────────────────

def test_footer_lines_status_msg_takes_priority():
    lines = proxyctl._tui_footer_lines(
        status_msg=" Deleted 3 proxy(ies)", marked_ids=set(),
        sort_by_live=False, watchdog_on=False, width=80,
    )
    assert lines == [" Deleted 3 proxy(ies)"]


def test_footer_lines_marked_mode():
    lines = proxyctl._tui_footer_lines(
        status_msg="", marked_ids={1, 2, 3},
        sort_by_live=False, watchdog_on=False, width=80,
    )
    joined = " ".join(lines)
    assert "3 marked" in joined
    assert "Space: toggle" in joined
    assert "Q: quit" in joined


def test_footer_lines_default_mode_reflects_watchdog_state():
    on_lines = proxyctl._tui_footer_lines(
        status_msg="", marked_ids=set(),
        sort_by_live=False, watchdog_on=True, width=80,
    )
    off_lines = proxyctl._tui_footer_lines(
        status_msg="", marked_ids=set(),
        sort_by_live=False, watchdog_on=False, width=80,
    )
    assert "watchdog-off" in " ".join(on_lines)
    assert "watchdog-off" not in " ".join(off_lines)
    assert "W: watchdog" in " ".join(off_lines)


def test_footer_lines_default_mode_wraps_on_narrow_terminal():
    lines = proxyctl._tui_footer_lines(
        status_msg="", marked_ids=set(),
        sort_by_live=False, watchdog_on=False, width=30,
    )
    assert len(lines) > 1
    joined = " ".join(lines)
    assert "Q: quit" in joined
    assert "U: use" in joined
