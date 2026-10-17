"""Exercise installed CLI entry points from outside the source checkout."""

import os
from pathlib import Path
import subprocess
import sys
import sysconfig

import pytest

from iot_firmware_analyzer import __version__

pytestmark = pytest.mark.integration


@pytest.fixture(params=["module", "console"])
def command(request: pytest.FixtureRequest) -> list[str]:
    """Select the environment's installed module or console script."""
    if request.param == "module":
        return [sys.executable, "-I", "-m", "iot_firmware_analyzer"]
    filename = "iot-firmware-analyzer.exe" if os.name == "nt" else "iot-firmware-analyzer"
    executable = Path(sysconfig.get_path("scripts")) / filename
    assert executable.is_file(), "Install the package in the test environment first."
    return [str(executable)]


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], "usage:"),
        (["--help"], "usage:"),
        (["--version"], f"iot-firmware-analyzer {__version__}"),
        (["about"], "does not process firmware"),
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
