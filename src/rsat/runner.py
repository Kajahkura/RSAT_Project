"""Bounded, non-shell native command execution with explicit failure states."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    state: str = "OK"
    reason: str = ""
    duration_ms: int = 0


class CommandRunner:
    def __init__(self, timeout=10.0, deadline=60.0, output_limit=2_000_000):
        self.timeout = timeout
        self.ends_at = time.monotonic() + deadline
        self.output_limit = output_limit

    @property
    def remaining(self):
        return max(0.0, self.ends_at - time.monotonic())

    def resolve(self, executable):
        path = Path(executable)
        if path.is_absolute():
            return str(path) if path.is_file() else None
        if path.name != executable:
            return None
        if os.name == "nt":
            system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            candidates = [
                system / "System32" / executable,
                system / "System32" / (executable + ".exe"),
                system / "System32/OpenSSH" / (executable + ".exe"),
                system / "System32/WindowsPowerShell/v1.0/powershell.exe"
                if executable.lower() in {"powershell", "powershell.exe"}
                else system / "invalid",
            ]
            return next((str(p) for p in candidates if p.is_file()), None)
        # Exclude the working directory and user-controlled search paths for privileged native collection.
        return shutil.which(executable, path="/usr/sbin:/usr/bin:/sbin:/bin:/usr/libexec")

    def run(self, argv, timeout=None):
        start = time.monotonic()
        if not argv or not all(isinstance(x, str) and "\0" not in x for x in argv):
            raise ValueError("Command must be a nonempty argument list")
        budget = min(timeout or self.timeout, self.remaining)
        if budget <= 0:
            return CommandResult(state="UNKNOWN", reason="Audit deadline reached")
        executable = self.resolve(argv[0])
        if executable is None:
            return CommandResult(state="UNKNOWN", reason=f"Utility unavailable: {argv[0]}")
        kwargs = (
            {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
        )
        # Temporary files avoid unbounded subprocess pipe buffers; reject output above the cap.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                process = subprocess.Popen(
                    [executable, *argv[1:]],
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    shell=False,
                    **kwargs,
                )
                reason = ""
                while process.poll() is None:
                    if time.monotonic() - start > budget:
                        reason = "Command timed out"
                        break
                    if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > self.output_limit:
                        reason = "Command output exceeded limit"
                        break
                    time.sleep(0.02)
                if reason:
                    if os.name == "nt":
                        # Kill descendants too; the fixed PID is supplied as a separate argument.
                        killer = self.resolve("taskkill")
                        if killer:
                            subprocess.run(
                                [killer, "/PID", str(process.pid), "/T", "/F"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=3,
                                check=False,
                            )
                    else:
                        import signal

                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.kill()
                process.wait(timeout=3)
                out.seek(0)
                err.seek(0)
                stdout = out.read(self.output_limit + 1)
                stderr = err.read(self.output_limit + 1)
                if len(stdout) + len(stderr) > self.output_limit:
                    reason = "Command output exceeded limit"
                state = "UNKNOWN" if reason else ("OK" if process.returncode == 0 else "ERROR")
                if not reason and process.returncode:
                    reason = f"Native query failed (exit {process.returncode}); permissions or platform support may be required"
                return CommandResult(
                    stdout.decode("utf-8-sig", errors="replace"),
                    stderr.decode("utf-8-sig", errors="replace"),
                    process.returncode,
                    state,
                    reason,
                    int((time.monotonic() - start) * 1000),
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return CommandResult(
                    state="ERROR",
                    reason=f"Command execution failed: {type(exc).__name__}",
                    duration_ms=int((time.monotonic() - start) * 1000),
                )

    def powershell(self, script):
        prefix = (
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
        )
        return self.run(
            ["powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + script]
        )


def parse_json(result):
    if result.state != "OK":
        raise ValueError(result.reason)
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Native query returned invalid JSON") from exc


def rows(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
