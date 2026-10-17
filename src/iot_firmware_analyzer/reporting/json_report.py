"""Versioned JSON metadata export with exclusive, rollback-on-error file writes."""

from dataclasses import asdict
import json
import logging
import os
from pathlib import Path
import stat

from iot_firmware_analyzer import __version__
from iot_firmware_analyzer.core.errors import InspectionError
from iot_firmware_analyzer.firmware.models import FirmwareMetadata

LOGGER = logging.getLogger(__name__)


def metadata_json(metadata: FirmwareMetadata) -> str:
    """Serialize fixed metadata fields; never include input bytes or tool descriptions."""
    document = asdict(metadata)
    document["schema_version"] = "1.0"
    document["tool"] = {"name": "iot-firmware-security-analyzer", "version": __version__}
    signatures = (*metadata.signatures, *metadata.binwalk.signatures)
    document["compression"] = sorted({match.name for match in signatures if match.category == "compression"})
    document["filesystems"] = sorted({match.name for match in signatures if match.category == "filesystem"})
    document["limitations"] = [
        "Signature observations do not establish image validity or exploitability.",
        "No firmware execution or extraction is requested.",
        "Built-in inspection does not decompress; optional Binwalk parsers may do so internally.",
        "Architecture describes only a consistent outer ELF header, when present.",
        "Unknown or absent signatures do not prove a format or component is absent.",
    ]
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def write_metadata_json(path: Path, document: str) -> None:
    """Create a report without overwriting existing files or following output links.

    Missing parent directories are created without following links. Exclusive
    creation prevents replacing the input image or another report. Failed writes
    remove only the newly created output file.
    """
    if str(path).startswith(("\\\\", "//")):
        raise InspectionError("invalid_output", "Network and device report paths are not supported.")
    created = False
    try:
        absolute = path.absolute()
        for component in reversed((absolute.parent, *absolute.parent.parents)):
            component.mkdir(mode=0o700, exist_ok=True)
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise InspectionError("invalid_output", "Report paths must not contain links.")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(absolute, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(document)
        LOGGER.info("JSON report saved")
    except InspectionError:
        raise
    except FileExistsError:
        raise InspectionError("output_exists", "Report destination already exists; choose a new file.") from None
    except (OSError, ValueError):
        if created:
            try:
                absolute.unlink()
            except OSError:
                pass
        raise InspectionError("output_unwritable", "Unable to create the JSON report destination.") from None
