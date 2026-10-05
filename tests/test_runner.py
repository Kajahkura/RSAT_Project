import sys
import time
from pathlib import Path
import pytest

from rsat.runner import CommandRunner, CommandResult, parse_json, rows


def test_missing_command_explicit():
    result = CommandRunner().run(["rsat-does-not-exist"])
    assert result.state == "UNKNOWN" and "unavailable" in result.reason


def test_deadline_skips_command():
    result = CommandRunner(deadline=0).run([sys.executable, "-c", "print(1)"])
    assert result.state == "UNKNOWN" and "deadline" in result.reason


def test_timeout_kills_command():
    start = time.monotonic()
    result = CommandRunner(timeout=0.15).run([sys.executable, "-c", "import time; time.sleep(5)"])
    assert result.state == "UNKNOWN" and "timed out" in result.reason
    assert time.monotonic() - start < 4


def test_command_failures_preserved():
    result = CommandRunner(timeout=30, deadline=40).run(
        [sys.executable, "-c", "import sys;print('err',file=sys.stderr);sys.exit(7)"]
    )
    assert result.state == "ERROR" and result.returncode == 7 and "err" in result.stderr


def test_output_is_bounded():
    result = CommandRunner(output_limit=100).run([sys.executable, "-c", "print('x'*10000)"])
    assert result.state == "UNKNOWN" and "limit" in result.reason


def test_argument_boundaries():
    text = "space ' $() & | `"
    result = CommandRunner(timeout=30, deadline=40).run(
        [sys.executable, "-c", "import sys;print(sys.argv[1])", text]
    )
    assert result.state == "OK" and result.stdout.strip() == text


def test_no_working_directory_utility_resolution(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("evil").write_text("fake")
    assert CommandRunner().resolve("evil") is None


def test_json_decoder():
    assert parse_json(CommandResult(stdout='{"a":1}')) == {"a": 1}
    assert rows({"a": 1}) == [{"a": 1}]
    assert rows(None) == []
    with pytest.raises(ValueError):
        parse_json(CommandResult(stdout="not-json"))


def test_capped_process_exit_during_cleanup_preserves_outcome():
    from unittest.mock import Mock, patch

    process = Mock(returncode=0)
    process.poll.return_value = None
    process.kill.side_effect = ProcessLookupError()
    with (
        patch("rsat.runner.subprocess.Popen", return_value=process),
        patch("rsat.runner.os.fstat", return_value=Mock(st_size=1000)),
        patch("rsat.runner.os.killpg", side_effect=ProcessLookupError(), create=True),
    ):
        result = CommandRunner(output_limit=100).run([sys.executable, "-c", "print('synthetic')"])
    assert result.state == "UNKNOWN" and "output exceeded limit" in result.reason
