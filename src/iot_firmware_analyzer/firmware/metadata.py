"""Bounded, streaming inspection of an untrusted regular file."""

from contextlib import contextmanager
import hashlib
import logging
import os
from pathlib import Path
import stat
import tempfile
import time
from collections.abc import Iterator
from typing import BinaryIO

from iot_firmware_analyzer.core.config import InspectionLimits
from iot_firmware_analyzer.core.errors import InspectionError
from iot_firmware_analyzer.firmware.binwalk import MAX_BINWALK_BYTES, identify_with_binwalk
from iot_firmware_analyzer.firmware.models import BinwalkResult, FirmwareMetadata
from iot_firmware_analyzer.firmware.signatures import (
    HEADER_BYTES,
    OVERLAP_BYTES,
    elf_architecture,
    header_signatures,
    outer_format,
    scan_chunk,
)

LOGGER = logging.getLogger(__name__)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """Compare identity and mutation indicators without reporting local paths."""
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    # Windows path and handle stat APIs disagree about the deprecated ctime field.
    return identity if os.name == "nt" else (*identity, info.st_ctime_ns)


def _check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise InspectionError("inspection_timeout", "Inspection exceeded its time limit.")


@contextmanager
def _open_regular(path: Path) -> Iterator[BinaryIO]:
    """Reject special files, links/reparse points and detectable open-time races."""
    if str(path).startswith(("\\\\", "//")):
        raise InspectionError("invalid_input", "Network and device paths are not supported.")
    try:
        absolute = path.absolute()
        for component in (absolute, *absolute.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise InspectionError("invalid_input", "Input paths must not contain links.")
        before = absolute.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise InspectionError("invalid_input", "Input must be a regular file.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(absolute, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _identity(before) != _identity(opened):
                raise InspectionError("input_changed", "Input changed while being opened.")
            yield stream
            if _identity(opened) != _identity(os.fstat(stream.fileno())):
                raise InspectionError("input_changed", "Input changed during inspection.")
            if _identity(opened) != _identity(absolute.lstat()):
                raise InspectionError("input_changed", "Input path changed during inspection.")
    except InspectionError:
        raise
    except (OSError, ValueError):
        raise InspectionError("input_unreadable", "Unable to read the input regular file.") from None


def inspect_firmware(
    path: Path,
    limits: InspectionLimits | None = None,
    *,
    use_binwalk: bool = False,
) -> FirmwareMetadata:
    """Hash and inspect one file; never execute firmware or request extraction.

    A private snapshot is created only for an explicitly requested Binwalk run,
    so that the external parser sees the exact bytes hashed by this inspection.
    """
    limits = limits or InspectionLimits()
    deadline = time.monotonic() + limits.timeout_seconds
    LOGGER.info("Starting read-only firmware inspection")
    try:
        with tempfile.TemporaryDirectory(prefix="iotfw-") if use_binwalk else _no_snapshot() as work:
            snapshot = Path(work) / "image.bin" if work is not None else None
            with _open_regular(path) as stream:
                size = os.fstat(stream.fileno()).st_size
                if size > limits.max_file_bytes:
                    raise InspectionError("input_too_large", "Input exceeds the configured size limit.")
                LOGGER.debug("Validated regular input: %d bytes", size)
                tool = BinwalkResult()
                if snapshot is not None and size > MAX_BINWALK_BYTES:
                    snapshot = None
                    tool = BinwalkResult("input_limit", warnings=("binwalk_input_exceeds_64_mib",))
                digest = hashlib.sha256()
                matches = []
                truncated = False
                prefix = b""
                tail = b""
                processed = 0
                with _snapshot_writer(snapshot) as copy:
                    while True:
                        _check_deadline(deadline)
                        chunk = stream.read(min(limits.chunk_bytes, limits.max_file_bytes - processed + 1))
                        if not chunk:
                            break
                        if processed + len(chunk) > limits.max_file_bytes:
                            raise InspectionError("input_too_large", "Input exceeded its size limit while reading.")
                        digest.update(chunk)
                        if copy is not None:
                            copy.write(chunk)
                        if len(prefix) < HEADER_BYTES:
                            prefix += chunk[: HEADER_BYTES - len(prefix)]
                        if not truncated:
                            observed, overflow = scan_chunk(
                                tail + chunk, processed - len(tail), processed,
                                limits.max_signatures - len(matches),
                            )
                            matches.extend(observed)
                            truncated |= overflow
                        tail = (tail + chunk)[-OVERLAP_BYTES:]
                        processed += len(chunk)
                        LOGGER.debug("Hashed and inspected %d bytes", processed)
                if processed != size:
                    raise InspectionError("input_changed", "Input size changed during inspection.")
                _check_deadline(deadline)
            fixed = header_signatures(prefix)
            all_matches = sorted(matches + fixed, key=lambda match: (match.offset, match.name))
            truncated |= len(all_matches) > limits.max_signatures
            matches = all_matches[: limits.max_signatures]
            architecture, warnings = elf_architecture(prefix)
            if truncated:
                warnings += ("signature_limit_reached",)
            if snapshot is not None:
                _check_deadline(deadline)
                tool = identify_with_binwalk(snapshot, deadline, limits.max_signatures)
            result = FirmwareMetadata(
                size, digest.hexdigest(), outer_format(prefix, matches), architecture,
                tuple(matches), not truncated, warnings, tool,
            )
        LOGGER.info("Inspection completed: %d bytes, %d built-in signatures", size, len(matches))
        return result
    except InspectionError as error:
        LOGGER.debug("Inspection stopped with code %s", error.code)
        raise
    except OSError:
        raise InspectionError("inspection_io_error", "Inspection storage operation failed.") from None


@contextmanager
def _no_snapshot() -> Iterator[None]:
    """Avoid creating any working directory for built-in inspection."""
    yield None


@contextmanager
def _snapshot_writer(path: Path | None) -> Iterator[BinaryIO | None]:
    """Create a private, exclusive snapshot only when the external tool is requested."""
    if path is None:
        yield None
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            yield stream
