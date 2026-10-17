"""Verify JSON schema, content minimization and non-destructive report creation."""

import json
from pathlib import Path

import pytest

from iot_firmware_analyzer.core.errors import InspectionError
from iot_firmware_analyzer.firmware.metadata import inspect_firmware
from iot_firmware_analyzer.reporting.json_report import metadata_json, write_metadata_json


def test_json_structure_and_content_minimization(tmp_path: Path) -> None:
    image = tmp_path / "SYNTHETIC_PRIVATE_FILENAME"
    image.write_bytes(b"hsqs\x00\x1f\x8b\x08SYNTHETIC_PRIVATE_CONTENT")
    document = metadata_json(inspect_firmware(image))
    result = json.loads(document)
    assert result["schema_version"] == "1.0"
    assert result["size_bytes"] == image.stat().st_size
    assert len(result["sha256"]) == 64
    assert result["architecture"] is None
    assert result["compression"] == ["gzip"]
    assert result["filesystems"] == ["squashfs"]
    assert result["binwalk"]["status"] == "not_requested"
    assert "SYNTHETIC_PRIVATE" not in document


def test_nested_output_and_existing_input_preserved(tmp_path: Path) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"artificial")
    original = image.read_bytes()
    document = metadata_json(inspect_firmware(image))
    output = tmp_path / "reports" / "metadata.json"
    write_metadata_json(output, document)
    assert json.loads(output.read_text(encoding="utf-8"))["size_bytes"] == len(original)
    for destination in (image, output):
        before = destination.read_bytes()
        with pytest.raises(InspectionError) as result:
            write_metadata_json(destination, document)
        assert result.value.code == "output_exists"
        assert destination.read_bytes() == before
    assert image.read_bytes() == original


def test_network_output_rejected() -> None:
    with pytest.raises(InspectionError) as result:
        write_metadata_json(Path("//SYNTHETIC_PRIVATE_SERVER/report"), "{}")
    assert result.value.code == "invalid_output"


def test_output_symlink_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"preserve")
    link = tmp_path / "report.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Creating symlinks requires unavailable Windows privileges.")
    with pytest.raises(InspectionError):
        write_metadata_json(link, "{}")
    assert target.read_bytes() == b"preserve"
