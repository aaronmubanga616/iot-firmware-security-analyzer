"""Dependency-free command-line entry point for the project foundation."""

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from iot_firmware_analyzer import __version__

PROGRAM_NAME = "iot-firmware-analyzer"
PROJECT_NAME = "IoT Firmware Reverse Engineering and Security Analyzer"
ABOUT_TEXT = f"""{PROJECT_NAME}
Version: {__version__}
Status: foundation / pre-alpha

Available: CLI help, version and project information.
Planned: firmware identification, metadata, safe extraction, static inventories,
unverified security candidates, and JSON/HTML/Markdown reporting.
Initial planned research target: OWASP IoTGoat (not bundled or downloaded).

Analyze only legally acquired firmware within your authorization.
Never execute extracted firmware binaries during static analysis.
Never print actual credentials, private keys or password hashes.
All future security findings remain unverified until manually validated.
Downloads, network activity and privileged actions require explicit approval.

This release does not process firmware or produce security findings.
"""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Avoid reflecting potentially sensitive user arguments in error messages."""

    def error(self, message: str) -> NoReturn:
        """Display a fixed diagnostic without exposing rejected argument values."""
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid command or arguments; use --help.\n")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without accessing firmware or external services."""
    parser = _SafeArgumentParser(
        prog=PROGRAM_NAME,
        description=f"{PROJECT_NAME}: static research framework (foundation).",
        epilog=(
            "Firmware analysis is not implemented yet. "
            "Use 'about' for capabilities and research safeguards."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", title="commands")
    commands.add_parser(
        "about",
        help="show project status, planned capabilities and research safeguards",
        description="Display project information without processing firmware.",
        allow_abbrev=False,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; argparse handles help and invalid-argument exit codes."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "about":
        print(ABOUT_TEXT, end="")
    else:
        parser.print_help()
    return 0
