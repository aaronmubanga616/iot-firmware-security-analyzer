"""Use synthetic JSON and controlled child programs; no installed Binwalk required."""

import json
import os
from pathlib import Path
import sys
import time

import pytest

from iot_firmware_analyzer.firmware import binwalk


def _log(snapshot: Path, entries: list[dict[str, object]]) -> bytes:
    return json.dumps([{"Analysis": {"file_path": str(snapshot), "file_map": entries, "extractions": {}}}]).encode()


def test_missing_binwalk_is_optional(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(binwalk.shutil, "which", lambda _: None)
    result = binwalk.identify_with_binwalk(tmp_path / "fixture", time.monotonic() + 10, 5)
    assert result.status == "unavailable"
    assert result.signatures == ()


def test_platform_resource_limits_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(binwalk.shutil, "which", lambda _: "/trusted/binwalk")
    monkeypatch.setattr(binwalk.sys, "platform", "win32")
    result = binwalk.identify_with_binwalk(tmp_path / "fixture", time.monotonic() + 10, 5)
    assert result.status == "unsupported_platform"


@pytest.mark.parametrize("version,status", [(b"binwalk 2.3.4\n", "unsupported_version"),
                                           (b"unrecognized output", "unsupported_version"),
                                           (b"binwalk 3.1.0\n", "completed")])
def test_version_and_signature_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: bytes, status: str
) -> None:
    snapshot = tmp_path / "image.bin"
    snapshot.write_bytes(b"\x00" * 64)
    monkeypatch.setattr(binwalk.shutil, "which", lambda _: "/trusted/binwalk")
    monkeypatch.setattr(binwalk.sys, "platform", "linux")
    calls: list[list[str]] = []

    def fake(arguments: list[str], work: Path, deadline: float) -> bytes:
        calls.append(arguments)
        assert work == tmp_path
        if "--version" in arguments:
            return version
        assert arguments[1:] == ["--quiet", "--threads", "1", "--log", "-", "--", str(snapshot)]
        assert "--extract" not in arguments and "--carve" not in arguments
        return _log(snapshot, [{"name": "gzip", "offset": 8, "description": "SYNTHETIC_PRIVATE_MARKER"}])

    monkeypatch.setattr(binwalk, "_run_bounded", fake)
    result = binwalk.identify_with_binwalk(snapshot, time.monotonic() + 30, 5)
    assert result.status == status
    if status == "completed":
        assert len(calls) == 2
        assert result.signatures[0].name == "gzip"
        assert result.signatures[0].offset == 8
        assert "SYNTHETIC_PRIVATE_MARKER" not in repr(result)
    else:
        assert len(calls) == 1


@pytest.mark.parametrize("failure", ["timeout", "output_limit", "failed"])
def test_optional_process_failures_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    snapshot = tmp_path / "image.bin"
    snapshot.write_bytes(b"artificial")
    monkeypatch.setattr(binwalk.shutil, "which", lambda _: "/trusted/binwalk")
    monkeypatch.setattr(binwalk.sys, "platform", "linux")

    def fail(*args: object) -> bytes:
        raise binwalk._ToolFailure(failure)

    monkeypatch.setattr(binwalk, "_run_bounded", fail)
    result = binwalk.identify_with_binwalk(snapshot, time.monotonic() + 10, 5)
    assert result.status == failure
    assert result.warnings == (f"binwalk_{failure}",)


@pytest.mark.parametrize("entry", [
    {"name": "gzip", "offset": -1}, {"name": "gzip", "offset": 64},
    {"name": "gzip", "offset": True}, {"name": "gzip", "offset": "8"},
    {"name": [], "offset": 1},
])
def test_invalid_offsets_and_names_rejected(tmp_path: Path, entry: dict[str, object]) -> None:
    snapshot = tmp_path / "image.bin"
    snapshot.write_bytes(b"\x00" * 64)
    with pytest.raises(binwalk._ToolFailure, match="invalid_output"):
        binwalk._parse_log(_log(snapshot, [entry]), snapshot, 5)


@pytest.mark.parametrize("document", [[], {}, [{"Analysis": {}}], [{"Entropy": {}}]])
def test_malformed_envelopes_rejected(tmp_path: Path, document: object) -> None:
    with pytest.raises(binwalk._ToolFailure, match="invalid_output"):
        binwalk._parse_log(json.dumps(document).encode(), tmp_path / "image.bin", 5)


def test_tool_free_text_redacted_and_results_capped(tmp_path: Path) -> None:
    snapshot = tmp_path / "image.bin"
    snapshot.write_bytes(b"\x00" * 64)
    output = _log(snapshot, [{"name": "SYNTHETIC_PRIVATE_MARKER", "offset": n,
                              "description": "SYNTHETIC_PRIVATE_CONTENT"} for n in range(4)])
    matches, warnings = binwalk._parse_log(output, snapshot, 2)
    assert len(matches) == 2
    assert all(match.name == "other" for match in matches)
    assert "SYNTHETIC_PRIVATE" not in repr(matches)
    assert "binwalk_signature_limit_reached" in warnings


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process/resource boundary required")
@pytest.mark.parametrize("mode", ["success", "timeout", "output_limit", "memory_limit"])
def test_real_child_process_bounds(tmp_path: Path, mode: str) -> None:
    """Launch only trusted test code, never firmware, through the real resource launcher."""
    script = {"success": "import sys; sys.stdout.write('bounded')",
              "timeout": "import time; time.sleep(10)",
              "output_limit": "import sys; sys.stdout.buffer.write(b'x' * 2000000)",
              "memory_limit": "try:\n x = bytearray(800 * 1024**2)\nexcept MemoryError:\n print('bounded', end='')"}[mode]
    command = [sys.executable, "-I", "-c", script]
    deadline = time.monotonic() + (0.5 if mode == "timeout" else 5)
    if mode in ("success", "memory_limit"):
        assert binwalk._run_bounded(command, tmp_path, deadline) == b"bounded"
    else:
        with pytest.raises(binwalk._ToolFailure, match=mode):
            binwalk._run_bounded(command, tmp_path, deadline)
