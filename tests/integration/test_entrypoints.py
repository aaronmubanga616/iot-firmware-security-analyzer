"""Exercise installed CLI entry points from outside the source checkout."""

import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import sysconfig

import pytest

from iot_firmware_analyzer import __version__

pytestmark = pytest.mark.integration


@pytest.fixture(params=["module", "console", "short-console"])
def command(request: pytest.FixtureRequest) -> list[str]:
    """Select the environment's installed module or console script."""
    if request.param == "module":
        return [sys.executable, "-I", "-m", "iot_firmware_analyzer"]
    name = "iotfw" if request.param == "short-console" else "iot-firmware-analyzer"
    filename = f"{name}.exe" if os.name == "nt" else name
    executable = Path(sysconfig.get_path("scripts")) / filename
    assert executable.is_file(), "Install the package in the test environment first."
    return [str(executable)]


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], "usage:"),
        (["--help"], "usage:"),
        (["--version"], __version__),
        (["about"], "does not extract firmware"),
        (["about", "--help"], "without processing firmware"),
    ],
)
def test_installed_entrypoints(
    command: list[str], arguments: list[str], expected: str, tmp_path: Path
) -> None:
    """Installed commands work without relying on the checkout working directory."""
    result = subprocess.run(
        [*command, *arguments],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout
    assert result.stderr == ""
    assert list(tmp_path.iterdir()) == []


def test_firmware_input_is_rejected_without_modification(
    command: list[str], tmp_path: Path
) -> None:
    """The foundation does not pretend to analyze or modify a synthetic image."""
    firmware = tmp_path / "SYNTHETIC_PRIVATE_IMAGE.bin"
    content = b"Synthetic firmware fixture; not executable.\n"
    firmware.write_bytes(content)
    result = subprocess.run(
        [*command, "analyze", str(firmware)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid command or arguments" in result.stderr
    assert firmware.name not in result.stderr
    assert firmware.read_bytes() == content
    assert list(tmp_path.iterdir()) == [firmware]


@pytest.mark.parametrize("use_file", [True, False])
def test_inspect_json_entrypoints(command: list[str], tmp_path: Path, use_file: bool) -> None:
    """Actual installed commands produce JSON and keep logs off stdout."""
    firmware = tmp_path / "SYNTHETIC_PRIVATE_FILENAME.bin"
    content = b"hsqs\x00\x1f\x8b\x08SYNTHETIC_PRIVATE_CONTENT"
    firmware.write_bytes(content)
    output = tmp_path / "reports" / "metadata.json"
    arguments = ["inspect", str(firmware), "--verbose"]
    if use_file:
        arguments += ["--output", str(output)]
    result = subprocess.run([*command, *arguments], cwd=tmp_path, capture_output=True,
                            text=True, encoding="utf-8", timeout=15, check=False)
    assert result.returncode == 0, result.stderr
    document = output.read_text(encoding="utf-8") if use_file else result.stdout
    report = json.loads(document)
    assert report["size_bytes"] == len(content)
    assert report["sha256"] == hashlib.sha256(content).hexdigest()
    assert report["image_format"] == "squashfs"
    assert report["compression"] == ["gzip"]
    assert report["filesystems"] == ["squashfs"]
    assert report["architecture"] is None
    assert report["binwalk"]["status"] == "not_requested"
    assert "SYNTHETIC_PRIVATE" not in document + result.stdout + result.stderr
    assert "DEBUG" in result.stderr
    if use_file:
        assert result.stdout == ""
    assert firmware.read_bytes() == content


def test_inspect_missing_input_has_graceful_error(command: list[str], tmp_path: Path) -> None:
    result = subprocess.run(
        [*command, "inspect", str(tmp_path / "SYNTHETIC_PRIVATE_FILENAME")],
        capture_output=True, text=True, encoding="utf-8", timeout=15, check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert "input_unreadable" in result.stderr
    assert "Traceback" not in result.stderr
    assert "SYNTHETIC_PRIVATE" not in result.stderr
