from __future__ import annotations

import os
import signal
import time
from pathlib import Path

import pytest

from auth_picker.errors import ProcessFailed
from auth_picker.proc import run

SH = "/bin/sh"


def _wait_dead(pid: int, within: float = 3.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def test_relative_program_is_refused() -> None:
    with pytest.raises(ValueError, match="absolute"):
        run(["sh", "-c", "true"])


def test_input_goes_through_stdin_and_exit_code_is_kept() -> None:
    result = run([SH, "-c", "cat; exit 3"], input=b"secret-on-stdin")
    assert result.returncode == 3
    assert result.stdout == b"secret-on-stdin"
    assert "secret" not in repr(result)


def test_large_input_and_output_do_not_deadlock() -> None:
    payload = os.urandom(2 * 1024 * 1024)
    result = run(["/bin/cat"], input=payload, timeout=20)
    assert result.ok
    assert result.stdout == payload


def test_returns_when_command_exits_even_if_a_child_keeps_the_pipes() -> None:
    # The original plugin waited for end-of-file here, for hours.
    started = time.monotonic()
    result = run([SH, "-c", "sleep 30 & echo $!"], timeout=20)
    elapsed = time.monotonic() - started
    pid = int(result.stdout.split()[0])
    try:
        assert result.ok
        assert elapsed < 3
    finally:
        os.kill(pid, signal.SIGKILL)


def test_timeout_kills_the_whole_process_group(tmp_path: Path) -> None:
    pidfile = tmp_path / "pid"
    with pytest.raises(ProcessFailed) as caught:
        run([SH, "-c", f"sleep 30 & echo $! > {pidfile}; wait"], timeout=0.5)
    assert caught.value.code == "timeout"
    assert _wait_dead(int(pidfile.read_text()))


def test_runaway_output_is_cut_off() -> None:
    with pytest.raises(ProcessFailed) as caught:
        run(["/usr/bin/yes"], max_output=256 * 1024, timeout=20)
    assert caught.value.code == "output"


def test_missing_program_is_a_typed_error() -> None:
    with pytest.raises(ProcessFailed) as caught:
        run(["/nonexistent/program"])
    assert caught.value.code == "spawn"
