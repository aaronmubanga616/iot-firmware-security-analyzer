"""Exercise real bounded reads of synthetic data and hostile input paths."""

from collections.abc import Callable
import hashlib
import logging
import os
from pathlib import Path
import time

import pytest

from iot_firmware_analyzer.core.config import InspectionLimits
from iot_firmware_analyzer.core.errors import InspectionError
from iot_firmware_analyzer.firmware import metadata
from iot_firmware_analyzer.firmware.models import BinwalkResult


@pytest.mark.parametrize("content,expected", [(b"", "empty"), (b"artificial bytes", "unknown")])
def test_size_hash_and_unknown(tmp_path: Path, content: bytes, expected: str) -> None:
    """Unknown and empty inputs have exact hashes without guessed metadata."""
    image = tmp_path / "arm-mips-linux.bin"
    image.write_bytes(content)
    result = metadata.inspect_firmware(image)
    assert result.size_bytes == len(content)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.image_format == expected
    assert result.architecture is None
    assert result.signatures == ()
    assert result.signature_scan_complete
    assert result.binwalk.status == "not_requested"


@pytest.mark.parametrize(
    "magic,name,category",
    [
        (b"\x7fELF", "elf", "executable"),
        (b"\x27\x05\x19\x56", "u-boot-legacy", "image"),
        (b"HDR0", "trx", "image"),
        (b"\xd0\x0d\xfe\xed", "flattened-device-tree", "image"),
        (b"UBI#", "ubi", "image"),
        (b"hsqs", "squashfs", "filesystem"),
        (b"sqsh", "squashfs", "filesystem"),
        (b"\x31\x18\x10\x06", "ubifs", "filesystem"),
        (b"\x1f\x8b\x08", "gzip", "compression"),
        (b"\xfd7zXZ\x00", "xz", "compression"),
        (b"BZh9", "bzip2", "compression"),
        (b"\x04\x22\x4d\x18", "lz4-frame", "compression"),
        (b"\x28\xb5\x2f\xfd", "zstd", "compression"),
        (b"PK\x03\x04", "zip", "archive"),
    ],
)
def test_signature_only_observations(
    tmp_path: Path, magic: bytes, name: str, category: str
) -> None:
    """A header match is recorded even when the synthetic image is not valid."""
    image = tmp_path / "fixture"
    image.write_bytes(magic + b"\x00" * 80)
    result = metadata.inspect_firmware(image)
    assert result.image_format == name
    assert result.signatures[0].name == name
    assert result.signatures[0].category == category
    assert result.signatures[0].offset == 0
    assert "unverified" in result.signatures[0].evidence
    assert result.architecture is None


def test_embedded_and_chunk_boundary_matches(tmp_path: Path) -> None:
    """Embedded signatures across read boundaries are neither missed nor duplicated."""
    content = b"\x00" * 4094 + b"\xfd7zXZ\x00" + b"\x00" * 23 + b"hsqs"
    image = tmp_path / "fixture"
    image.write_bytes(content)
    result = metadata.inspect_firmware(image, InspectionLimits(chunk_bytes=4096))
    assert result.image_format == "unknown"
    assert [(match.name, match.offset) for match in result.signatures] == [("xz", 4094), ("squashfs", 4123)]
    assert result.sha256 == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize("count,complete", [(2, True), (3, False), (3000, False)])
def test_signature_cap_preserves_full_hash(tmp_path: Path, count: int, complete: bool) -> None:
    """Repeated signatures cannot grow results without bound or truncate the hash."""
    content = b"hsqs\x00" * count
    image = tmp_path / "fixture"
    image.write_bytes(content)
    result = metadata.inspect_firmware(image, InspectionLimits(max_signatures=2, chunk_bytes=4096))
    assert len(result.signatures) == 2
    assert result.signature_scan_complete is complete
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert ("signature_limit_reached" in result.warnings) is not complete


@pytest.mark.parametrize("offset,magic,name", [(257, b"ustar\x00", "tar"), (1080, b"\x53\xef", "ext-family")])
def test_fixed_offset_headers(tmp_path: Path, offset: int, magic: bytes, name: str) -> None:
    """Fixed-offset signatures do not imply a more specific filesystem or FIT format."""
    image = tmp_path / "fixture"
    image.write_bytes(b"\x00" * offset + magic)
    result = metadata.inspect_firmware(image)
    assert result.image_format == name
    assert result.signatures[0].offset == offset


@pytest.mark.parametrize("order", ["little", "big"])
def test_jffs2_header_crc(tmp_path: Path, order: str) -> None:
    """Short JFFS2 magic requires an intact node header CRC."""
    import zlib

    prefix = (0x1985).to_bytes(2, order) + (0xE001).to_bytes(2, order) + (12).to_bytes(4, order)
    image = tmp_path / "fixture"
    image.write_bytes(prefix + zlib.crc32(prefix).to_bytes(4, order))
    assert metadata.inspect_firmware(image).image_format == "jffs2"
    image.write_bytes(prefix + b"\x00" * 4)
    assert metadata.inspect_firmware(image).image_format == "unknown"


@pytest.mark.parametrize(
    "machine,bits,order,name",
    [(40, 32, "little", "arm"), (8, 32, "big", "mips"), (183, 64, "little", "aarch64"),
     (62, 64, "little", "x86_64"), (243, 64, "little", "riscv")],
)
def test_elf_architecture_evidence(
    tmp_path: Path, make_elf: Callable[..., bytes], machine: int, bits: int, order: str, name: str
) -> None:
    """Architecture refers only to explicit machine/class/encoding fields of an outer ELF."""
    image = tmp_path / "fixture"
    image.write_bytes(make_elf(machine, bits, order))
    result = metadata.inspect_firmware(image)
    assert result.architecture is not None
    assert result.architecture.name == name
    assert result.architecture.elf_class_bits == bits
    assert result.architecture.endianness == order
    assert result.architecture.machine_id == machine


@pytest.mark.parametrize("mutation,warning", [
    ("short", "elf_header_incomplete"),
    ("encoding", "elf_header_invalid"),
    ("size", "elf_header_invalid"),
    ("version", "elf_header_invalid"),
    ("unknown", "elf_machine_unrecognized"),
    ("inconsistent", "elf_header_inconsistent_architecture"),
])
def test_no_architecture_from_unreliable_headers(
    tmp_path: Path, make_elf: Callable[..., bytes], mutation: str, warning: str
) -> None:
    """Truncation, contradictory fields and unknown IDs remain unknown."""
    content = bytearray(make_elf())
    if mutation == "short":
        content = content[:20]
    elif mutation == "encoding":
        content[5] = 0
    elif mutation == "size":
        content[40:42] = b"\x00\x00"
    elif mutation == "version":
        content[20] = 0
    elif mutation == "unknown":
        content[18:20] = (65535).to_bytes(2, "little")
    else:
        content[18:20] = (183).to_bytes(2, "little")
    image = tmp_path / "fixture"
    image.write_bytes(content)
    result = metadata.inspect_firmware(image)
    assert result.architecture is None
    assert warning in result.warnings


def test_embedded_elf_does_not_claim_device_architecture(tmp_path: Path, make_elf: Callable[..., bytes]) -> None:
    image = tmp_path / "arm-linux.img"
    image.write_bytes(b"padding" + make_elf())
    result = metadata.inspect_firmware(image)
    assert result.architecture is None
    assert result.image_format == "unknown"
    assert result.signatures[0].offset == 7


@pytest.mark.parametrize("kind", ["missing", "directory", "network", "nul"])
def test_invalid_paths_are_sanitized(tmp_path: Path, kind: str) -> None:
    paths = {"missing": tmp_path / "SYNTHETIC_PRIVATE_MARKER", "directory": tmp_path,
             "network": Path("//SYNTHETIC_PRIVATE_MARKER/share/image"), "nul": Path("invalid\x00path")}
    with pytest.raises(InspectionError) as result:
        metadata.inspect_firmware(paths[kind])
    assert "SYNTHETIC_PRIVATE_MARKER" not in str(result.value)


def test_input_size_limit_and_exact_boundary(tmp_path: Path) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"12345")
    assert metadata.inspect_firmware(image, InspectionLimits(max_file_bytes=5)).size_bytes == 5
    with pytest.raises(InspectionError, match="size limit"):
        metadata.inspect_firmware(image, InspectionLimits(max_file_bytes=4))


def test_read_permission_failure_is_sanitized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"artificial")

    def denied(*args: object, **kwargs: object) -> int:
        raise PermissionError("SYNTHETIC_PRIVATE_MARKER")

    monkeypatch.setattr(metadata.os, "open", denied)
    with pytest.raises(InspectionError) as result:
        metadata.inspect_firmware(image)
    assert result.value.code == "input_unreadable"
    assert "SYNTHETIC_PRIVATE_MARKER" not in str(result.value)


def test_mutation_during_read_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"artificial")
    scan = metadata.scan_chunk

    def mutate(*args: object) -> object:
        # Append instead of relying on coarse or filesystem-specific timestamp precision.
        if image.stat().st_size == len(b"artificial"):
            with image.open("ab") as stream:
                stream.write(b"changed")
        return scan(*args)

    monkeypatch.setattr(metadata, "scan_chunk", mutate)
    with pytest.raises(InspectionError) as result:
        metadata.inspect_firmware(image)
    assert result.value.code == "input_changed"


def test_deadline_stops_processing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"artificial")
    moments = iter((0.0, 61.0))
    monkeypatch.setattr(metadata.time, "monotonic", lambda: next(moments))
    with pytest.raises(InspectionError) as result:
        metadata.inspect_firmware(image)
    assert result.value.code == "inspection_timeout"


def test_logs_exclude_input_values(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    image = tmp_path / "SYNTHETIC_PRIVATE_FILENAME"
    image.write_bytes(b"SYNTHETIC_PRIVATE_CONTENT")
    with caplog.at_level(logging.DEBUG, logger="iot_firmware_analyzer"):
        metadata.inspect_firmware(image)
    assert "Starting read-only" in caplog.text
    assert "SYNTHETIC_PRIVATE" not in caplog.text


def test_binwalk_receives_private_hashed_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "SYNTHETIC_PRIVATE_FILENAME"
    content = b"artificial firmware"
    image.write_bytes(content)
    snapshots: list[Path] = []

    def fake(snapshot: Path, deadline: float, limit: int) -> BinwalkResult:
        assert snapshot != image
        assert snapshot.name == "image.bin"
        assert snapshot.read_bytes() == content
        assert deadline > time.monotonic()
        snapshots.append(snapshot)
        return BinwalkResult("completed", "3.1.0")

    monkeypatch.setattr(metadata, "identify_with_binwalk", fake)
    result = metadata.inspect_firmware(image, use_binwalk=True)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.binwalk.status == "completed"
    assert not snapshots[0].exists()
    assert image.read_bytes() == content


def test_no_external_tools_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"artificial")

    def unexpected(*args: object) -> None:
        raise AssertionError("External tool was invoked without explicit request.")

    monkeypatch.setattr(metadata, "identify_with_binwalk", unexpected)
    metadata.inspect_firmware(image)


def test_oversize_binwalk_input_skips_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    image = tmp_path / "fixture"
    image.write_bytes(b"artificial")
    monkeypatch.setattr(metadata, "MAX_BINWALK_BYTES", 1)
    result = metadata.inspect_firmware(image, use_binwalk=True)
    assert result.size_bytes == 10
    assert result.binwalk.status == "input_limit"


@pytest.mark.parametrize("kind", ["file_link", "directory_link"])
def test_symlink_paths_are_rejected(tmp_path: Path, kind: str) -> None:
    directory = tmp_path / "real"
    directory.mkdir()
    image = directory / "fixture"
    image.write_bytes(b"artificial")
    link = tmp_path / "link"
    try:
        link.symlink_to(image if kind == "file_link" else directory, target_is_directory=kind == "directory_link")
    except OSError:
        pytest.skip("Creating symlinks requires unavailable Windows privileges.")
    with pytest.raises(InspectionError) as result:
        metadata.inspect_firmware(link if kind == "file_link" else link / "fixture")
    assert result.value.code == "invalid_input"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO support required")
def test_fifo_is_rejected_without_opening(tmp_path: Path) -> None:
    image = tmp_path / "fifo"
    os.mkfifo(image)
    with pytest.raises(InspectionError) as result:
        metadata.inspect_firmware(image)
    assert result.value.code == "invalid_input"


@pytest.mark.parametrize("settings", [
    {"max_file_bytes": 0}, {"max_file_bytes": 17 * 1024**3}, {"chunk_bytes": 1},
    {"max_signatures": 0}, {"timeout_seconds": 0}, {"timeout_seconds": float("nan")},
    {"timeout_seconds": float("inf")}, {"timeout_seconds": 601},
])
def test_invalid_limits(settings: dict[str, int | float]) -> None:
    with pytest.raises(ValueError):
        InspectionLimits(**settings)
