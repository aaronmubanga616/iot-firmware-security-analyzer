"""Typed metadata records with no raw input strings or secret-bearing content."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    """An observed signature, not a claim that an image is valid or extractable."""

    name: str
    category: str
    offset: int
    source: str = "builtin"
    evidence: str = "magic signature only; image validity is unverified"


@dataclass(frozen=True)
class Architecture:
    """Architecture declared by a consistent outer ELF header, not the device CPU."""

    name: str
    elf_class_bits: int
    endianness: str
    machine_id: int
    offset: int = 0
    evidence: str = "ELF e_machine, EI_CLASS and EI_DATA; consistent ELF header"
    scope: str = "outer ELF header; does not establish the target device architecture"


@dataclass(frozen=True)
class BinwalkResult:
    """Sanitized optional-tool outcome; arbitrary tool descriptions are excluded."""

    status: str = "not_requested"
    version: str | None = None
    signatures: tuple[Signature, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class FirmwareMetadata:
    """A full-file hash and bounded observations from one validated streaming read."""

    size_bytes: int
    sha256: str
    image_format: str
    architecture: Architecture | None
    signatures: tuple[Signature, ...]
    signature_scan_complete: bool
    warnings: tuple[str, ...]
    binwalk: BinwalkResult
