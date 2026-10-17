"""Verify CLI behavior without firmware, external tools or network access."""

import pytest

from iot_firmware_analyzer import __version__
from iot_firmware_analyzer.core.cli import PROJECT_NAME, main


def test_no_arguments_displays_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Invoking the foundation without a subcommand is useful and successful."""
    assert main([]) == 0
    output = capsys.readouterr()
    assert "usage: iot-firmware-analyzer" in output.out
    assert "about" in output.out
    assert "inspect" in output.out
    assert output.err == ""


@pytest.mark.parametrize("arguments", [["--help"], ["-h"], ["about", "--help"], ["inspect", "--help"]])
def test_help_exits_successfully(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Both the root parser and the subcommand provide standard help."""
    with pytest.raises(SystemExit) as result:
        main(arguments)
    assert result.value.code == 0
    output = capsys.readouterr()
    assert "usage:" in output.out
    assert output.err == ""


def test_version_matches_installed_package(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The console version comes from installed distribution metadata."""
    with pytest.raises(SystemExit) as result:
        main(["--version"])
    assert result.value.code == 0
    output = capsys.readouterr()
    assert output.out.strip() == f"iot-firmware-analyzer {__version__}"
    assert output.err == ""


def test_about_describes_scope_and_safeguards(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Project information distinguishes the foundation from planned analysis."""
    assert main(["about"]) == 0
    output = capsys.readouterr()
    assert PROJECT_NAME in output.out
    assert "metadata inspection / pre-alpha" in output.out
    assert "does not extract firmware" in output.out
    assert "unverified until manually validated" in output.out
    assert "Never execute extracted firmware binaries" in output.out
    assert "Never print actual credentials" in output.out
    assert "require explicit approval" in output.out
    assert output.err == ""


@pytest.mark.parametrize(
    "arguments",
    [
        ["analyze"],
        ["extract"],
        ["--unknown"],
        ["--ver"],
        ["about", "--unknown"],
        ["about", "extra"],
    ],
)
def test_invalid_arguments_fail_without_claiming_analysis(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Unsupported operations and abbreviated options fail with exit code 2."""
    with pytest.raises(SystemExit) as result:
        main(arguments)
    assert result.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "invalid command or arguments" in output.err


@pytest.mark.parametrize(
    "arguments",
    [
        ["SYNTHETIC_SENSITIVE_MARKER"],
        ["about", "SYNTHETIC_SENSITIVE_MARKER"],
        ["--unexpected=SYNTHETIC_SENSITIVE_MARKER"],
    ],
)
def test_rejected_arguments_are_not_echoed(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Error output does not expose potentially sensitive argument values."""
    with pytest.raises(SystemExit) as result:
        main(arguments)
    assert result.value.code == 2
    output = capsys.readouterr()
    assert "SYNTHETIC_SENSITIVE_MARKER" not in output.out + output.err


@pytest.mark.parametrize("arguments", [
    ["inspect"], ["inspect", "fixture", "--timeout", "nan"],
    ["inspect", "fixture", "--timeout", "inf"], ["inspect", "fixture", "--timeout", "0"],
    ["inspect", "fixture", "--max-size-mib", "-1"],
    ["inspect", "fixture", "--max-size-mib", "16385"],
    ["inspect", "fixture", "--timeout", "SYNTHETIC_SENSITIVE_MARKER"],
])
def test_invalid_inspection_options(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as result:
        main(arguments)
    assert result.value.code == 2
    output = capsys.readouterr()
    assert "SYNTHETIC_SENSITIVE_MARKER" not in output.out + output.err
