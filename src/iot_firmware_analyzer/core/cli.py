"""Dependency-free CLI for bounded, read-only firmware inspection."""

import argparse
from contextlib import contextmanager
import logging
from pathlib import Path
import sys
from collections.abc import Iterator, Sequence
from typing import NoReturn

from iot_firmware_analyzer import __version__
from iot_firmware_analyzer.core.config import InspectionLimits
from iot_firmware_analyzer.core.errors import InspectionError
from iot_firmware_analyzer.firmware.metadata import inspect_firmware
from iot_firmware_analyzer.reporting.json_report import metadata_json, write_metadata_json

PROGRAM_NAME = "iot-firmware-analyzer"
PROJECT_NAME = "IoT Firmware Reverse Engineering and Security Analyzer"
ABOUT_TEXT = f"""{PROJECT_NAME}
Version: {__version__}
Status: metadata inspection / pre-alpha

Available: bounded read-only inspection, SHA-256, signature observations,
outer ELF architecture metadata, optional installed Binwalk 3, and JSON export.
Planned: safe extraction, static inventories, unverified security candidates,
and HTML/Markdown reporting.
Initial planned research target: OWASP IoTGoat (not bundled or downloaded).

Analyze only legally acquired firmware within your authorization.
Never execute extracted firmware binaries during static analysis.
Never print actual credentials, private keys or password hashes.
All future security findings remain unverified until manually validated.
Downloads, network activity and privileged actions require explicit approval.

This release does not extract firmware or produce security findings.
"""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Avoid reflecting potentially sensitive user arguments in error messages."""

    def error(self, message: str) -> NoReturn:
        """Display a fixed diagnostic without exposing rejected argument values."""
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid command or arguments; use --help.\n")


def build_parser(prog: str = PROGRAM_NAME) -> argparse.ArgumentParser:
    """Build the CLI parser without accessing firmware or external services."""
    parser = _SafeArgumentParser(
        prog=prog,
        description=f"{PROJECT_NAME}: bounded static metadata inspection.",
        epilog=(
            "Use 'inspect' for read-only metadata and 'about' for research safeguards. "
            "Extraction and security rules are not implemented."
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
    inspect = commands.add_parser(
        "inspect", help="inspect a regular firmware file and export JSON metadata",
        description="Read and hash firmware without executing or extracting it.",
        allow_abbrev=False,
    )
    inspect.add_argument("firmware", type=Path, help="local regular firmware image (links rejected)")
    inspect.add_argument("--output", type=Path, help="new JSON report path; default: JSON on stdout")
    inspect.add_argument("--binwalk", action="store_true", help="also use installed Binwalk 3 on Linux (no extraction)")
    inspect.add_argument("--max-size-mib", type=int, default=1024, help="maximum input MiB, 1-16384 (default: 1024)")
    inspect.add_argument("--timeout", type=float, default=60.0, help="time budget in seconds, >0 and <=600 (default: 60)")
    inspect.add_argument("--verbose", "-v", action="store_true", help="detailed sanitized progress logging to stderr")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; argparse handles help and invalid-argument exit codes."""
    prog = "iotfw" if argv is None and Path(sys.argv[0]).stem == "iotfw" else PROGRAM_NAME
    parser = build_parser(prog)
    args = parser.parse_args(argv)
    if args.command == "about":
        print(ABOUT_TEXT, end="")
    elif args.command == "inspect":
        try:
            limits = InspectionLimits(
                max_file_bytes=args.max_size_mib * 1024**2,
                timeout_seconds=args.timeout,
            )
        except ValueError:
            parser.error("Invalid inspection resource limits.")
        with _cli_logging(args.verbose) as logger:
            try:
                result = inspect_firmware(args.firmware, limits, use_binwalk=args.binwalk)
                document = metadata_json(result)
                if args.output is None:
                    sys.stdout.write(document)
                else:
                    write_metadata_json(args.output, document)
                if result.binwalk.status not in ("not_requested", "completed"):
                    logger.warning("Built-in results retained; Binwalk status: %s", result.binwalk.status)
                return 0
            except InspectionError as error:
                logger.error("%s: %s", error.code, error)
                return 1
            except BrokenPipeError:
                return 1
            except OSError:
                logger.error("output_unwritable: Unable to write JSON output.")
                return 1
            except KeyboardInterrupt:
                logger.error("inspection_interrupted: Inspection cancelled.")
                return 130
    else:
        parser.print_help()
    return 0


@contextmanager
def _cli_logging(verbose: bool) -> Iterator[logging.Logger]:
    """Keep JSON stdout clean and restore library logging configuration after use."""
    logger = logging.getLogger("iot_firmware_analyzer")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    old_level, old_propagate = logger.level, logger.propagate
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        yield logger
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(old_level)
        logger.propagate = old_propagate
