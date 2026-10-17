"""Optional Binwalk 3 signature-only adapter, without extraction or raw output.

The upstream CLI supports ``--quiet --threads 1 --log -`` for JSON on stdout.
JSON records use the ``Analysis.file_map`` envelope. See docs/inspection.md
for upstream references, limits and the Linux-only process boundary.
"""

import json
import logging
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time

from iot_firmware_analyzer.firmware.models import BinwalkResult, Signature

LOGGER = logging.getLogger(__name__)
MAX_BINWALK_BYTES = 64 * 1024**2
MAX_OUTPUT_BYTES = 1024**2
_KNOWN_NAMES = {
    "elf": ("elf", "executable"),
    "gzip": ("gzip", "compression"),
    "xz": ("xz", "compression"),
    "bzip2": ("bzip2", "compression"),
    "lzma": ("lzma", "compression"),
    "lz4": ("lz4-frame", "compression"),
    "zstd": ("zstd", "compression"),
    "squashfs": ("squashfs", "filesystem"),
    "jffs2": ("jffs2", "filesystem"),
    "ubifs": ("ubifs", "filesystem"),
    "ext": ("ext-family", "filesystem"),
    "ubi": ("ubi", "image"),
    "uimage": ("u-boot-legacy", "image"),
    "trx": ("trx", "image"),
    "dtb": ("flattened-device-tree", "image"),
    "tar": ("tar", "archive"),
    "zip": ("zip", "archive"),
}


class _ToolFailure(Exception):
    """Fixed, safe status code for an optional external parser failure."""


def _run_bounded(arguments: list[str], work: Path, deadline: float) -> bytes:
    """Run a Linux child with capped combined output and a killable process group."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _ToolFailure("timeout")
    launcher = Path(__file__).with_name("_binwalk_runner.py")
    command = [sys.executable, "-I", str(launcher), str(max(1, math.ceil(remaining))), *arguments]
    environment = {
        "PATH": os.defpath,
        "HOME": str(work),
        "XDG_CONFIG_HOME": str(work),
        "TMPDIR": str(work),
        "LC_ALL": "C",
        "LANG": "C",
        "NO_COLOR": "1",
        "RUST_BACKTRACE": "0",
    }
    with subprocess.Popen(
        command, cwd=work, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        start_new_session=True,
    ) as process:
        try:
            stdout = bytearray()
            total = 0
            with selectors.DefaultSelector() as selector:
                assert process.stdout is not None and process.stderr is not None
                for pipe in (process.stdout, process.stderr):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise _ToolFailure("timeout")
                    for key, _ in selector.select(timeout=min(0.05, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_OUTPUT_BYTES:
                            raise _ToolFailure("output_limit")
                        if key.fileobj is process.stdout:
                            stdout.extend(chunk)
            if process.wait() != 0:
                raise _ToolFailure("failed")
            return bytes(stdout)
        finally:
            # Also terminate any descendants that inherited pipes or survived the parser.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def _parse_log(
    output: bytes, snapshot: Path, limit: int
) -> tuple[tuple[Signature, ...], tuple[str, ...]]:
    """Validate the single-image envelope, offsets and types; redact all free text."""
    document = json.loads(output)
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise _ToolFailure("invalid_output")
    analysis = document[0].get("Analysis")
    if (
        not isinstance(analysis, dict)
        or analysis.get("file_path") != str(snapshot)
        or analysis.get("extractions") != {}
        or not isinstance(analysis.get("file_map"), list)
    ):
        raise _ToolFailure("invalid_output")
    size = snapshot.stat().st_size
    matches: list[Signature] = []
    warnings: set[str] = set()
    for entry in analysis["file_map"]:
        if not isinstance(entry, dict):
            raise _ToolFailure("invalid_output")
        offset, name = entry.get("offset"), entry.get("name")
        if type(offset) is not int or not 0 <= offset < size or not isinstance(name, str):
            raise _ToolFailure("invalid_output")
        if len(matches) >= limit:
            warnings.add("binwalk_signature_limit_reached")
            break
        known = _KNOWN_NAMES.get(name)
        if known is None:
            warnings.add("binwalk_unmapped_signature_names_redacted")
        normalized, category = known or ("other", "other")
        matches.append(
            Signature(normalized, category, offset, source="binwalk3",
                      evidence="external signature observation; raw descriptions omitted")
        )
    return tuple(matches), tuple(sorted(warnings))


def identify_with_binwalk(snapshot: Path, deadline: float, limit: int) -> BinwalkResult:
    """Optionally identify a bounded private snapshot; never install tools or extract."""
    executable = shutil.which("binwalk")
    if executable is None:
        return BinwalkResult("unavailable", warnings=("binwalk_not_installed",))
    if sys.platform != "linux":
        return BinwalkResult("unsupported_platform", warnings=("binwalk_requires_linux_resource_limits",))
    version: str | None = None
    try:
        if snapshot.stat().st_size > MAX_BINWALK_BYTES:
            return BinwalkResult("input_limit", warnings=("binwalk_input_exceeds_64_mib",))
        work = snapshot.parent
        tool_deadline = min(deadline, time.monotonic() + 20)
        LOGGER.info("Checking installed Binwalk version")
        output = _run_bounded([str(Path(executable).absolute()), "--version"], work,
                              min(tool_deadline, time.monotonic() + 3))
        match = re.fullmatch(rb"binwalk (3\.\d{1,4}\.\d{1,4})(?:[-+][A-Za-z0-9.-]{1,64})?\s*", output)
        if match is None:
            return BinwalkResult("unsupported_version", warnings=("binwalk_3_required",))
        version = match.group(1).decode("ascii")
        LOGGER.info("Running Binwalk 3 signature identification without extraction")
        output = _run_bounded(
            [str(Path(executable).absolute()), "--quiet", "--threads", "1", "--log", "-", "--", str(snapshot)],
            work, tool_deadline,
        )
        matches, warnings = _parse_log(output, snapshot, limit)
        LOGGER.debug("Retained %d sanitized Binwalk signatures", len(matches))
        return BinwalkResult("completed", version, matches, warnings)
    except _ToolFailure as error:
        status = str(error)
    except (ValueError, RecursionError, UnicodeError):
        status = "invalid_output"
    except (OSError, subprocess.SubprocessError):
        status = "failed"
    LOGGER.warning("Optional Binwalk identification did not complete: %s", status)
    return BinwalkResult(status, version, warnings=(f"binwalk_{status}",))
