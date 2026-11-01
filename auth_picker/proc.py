"""Run one external command, safely.

- argv is a list with an absolute program path: no shell, no PATH lookup.
- Secrets go in through ``input`` (a stdin pipe), never argv or environment.
- Output comes back through pipes held in memory, never temporary files.
- The command runs in its own session, so a timeout kills its whole group.
- We stop reading shortly after the command exits, even if a process it
  started still holds the pipes open (a daemon herdr spawns, for example).
  Waiting for end-of-file there is what wedged the original plugin.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from auth_picker.errors import ProcessFailed

DEFAULT_TIMEOUT_S = 30.0
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
# How long to keep draining the pipes after the command itself has exited.
EXIT_GRACE_S = 0.25
_CHUNK = 64 * 1024


@dataclass(frozen=True)
class Result:
    returncode: int
    # Output may hold secrets (a Keychain read), so keep it out of repr().
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


class _Pump:
    """Moves bytes between us and one child until it exits (plus a grace period)."""

    def __init__(
        self, proc: subprocess.Popen[bytes], name: str, input: bytes | None, max_output: int
    ) -> None:
        self.proc = proc
        self.name = name
        self.max_output = max_output
        self.out = bytearray()
        self.err = bytearray()
        self.selector = selectors.DefaultSelector()
        self.pending = memoryview(input) if input else None
        self.sinks: dict[int, bytearray] = {}
        if proc.stdout is None or proc.stderr is None:  # pragma: no cover - both are PIPE
            raise ProcessFailed("spawn", f"could not capture output of {name}")
        for stream, sink in ((proc.stdout, self.out), (proc.stderr, self.err)):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ)
            self.sinks[stream.fileno()] = sink
        if proc.stdin is not None:
            if self.pending:
                os.set_blocking(proc.stdin.fileno(), False)
                self.selector.register(proc.stdin, selectors.EVENT_WRITE)
            else:
                proc.stdin.close()

    def run(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        exited_at: float | None = None
        while True:
            now = time.monotonic()
            if now >= deadline:
                _kill_group(self.proc)
                raise ProcessFailed("timeout", f"{self.name} gave no answer in {timeout:g}s")
            if exited_at is None and self.proc.poll() is not None:
                exited_at = now
            idle = not self.selector.get_map()
            if exited_at is not None and (idle or now - exited_at >= EXIT_GRACE_S):
                return
            wait = min(0.05, deadline - now)
            if idle:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self.proc.wait(timeout=wait)
                continue
            for key, _mask in self.selector.select(timeout=wait):
                if key.fileobj is self.proc.stdin:
                    self._feed(key)
                else:
                    self._drain(key)

    def _feed(self, key: selectors.SelectorKey) -> None:
        stdin = self.proc.stdin
        if stdin is None or self.pending is None:  # pragma: no cover - registered only with both
            return
        try:
            written = os.write(key.fd, self.pending[:_CHUNK])
        except BlockingIOError:
            return
        except BrokenPipeError:
            written = len(self.pending)
        self.pending = self.pending[written:]
        if not self.pending:
            self.selector.unregister(key.fileobj)
            stdin.close()

    def _drain(self, key: selectors.SelectorKey) -> None:
        try:
            data = os.read(key.fd, _CHUNK)
        except BlockingIOError:
            return
        if not data:
            self.selector.unregister(key.fileobj)
            return
        self.sinks[key.fd].extend(data)
        if len(self.out) + len(self.err) > self.max_output:
            _kill_group(self.proc)
            raise ProcessFailed("output", f"{self.name} wrote more than {self.max_output} bytes")

    def close(self) -> None:
        self.selector.close()
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if pipe is not None:
                pipe.close()
        if self.proc.poll() is None:
            _kill_group(self.proc)
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=1)


def run(
    argv: Sequence[str],
    *,
    input: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    env: Mapping[str, str] | None = None,
    max_output: int = MAX_OUTPUT_BYTES,
) -> Result:
    """Run ``argv`` and return its exit status and output.

    Raises ProcessFailed when the command cannot start, outlives ``timeout``,
    or writes more than ``max_output`` bytes. A non-zero exit is not an error
    here: the caller decides what it means.
    """
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError("argv[0] must be an absolute path")
    name = os.path.basename(argv[0])
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            env=dict(env) if env is not None else None,
        )
    except OSError as exc:
        raise ProcessFailed("spawn", f"could not run {name}: {exc.strerror}") from None
    try:
        pump = _Pump(proc, name, input, max_output)
    except BaseException:  # pragma: no cover - only if setting up the pipes fails
        _kill_group(proc)
        proc.wait(timeout=1)
        raise
    try:
        pump.run(timeout)
    finally:
        pump.close()
    return Result(proc.returncode, bytes(pump.out), bytes(pump.err))
