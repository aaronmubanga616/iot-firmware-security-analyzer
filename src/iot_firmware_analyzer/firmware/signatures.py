"""Conservative byte signatures; no decompression, disassembly or execution."""

from dataclasses import dataclass

from iot_firmware_analyzer.firmware.models import Architecture, Signature


@dataclass(frozen=True)
class _Magic:
    """A recognized byte pattern and a fixed, safe display name."""

    magic: bytes
    name: str
    category: str


_MAGICS = (
    _Magic(b"\x7fELF", "elf", "executable"),
    _Magic(b"\x27\x05\x19\x56", "u-boot-legacy", "image"),
    _Magic(b"HDR0", "trx", "image"),
    _Magic(b"\xd0\x0d\xfe\xed", "flattened-device-tree", "image"),
    _Magic(b"UBI#", "ubi", "image"),
    _Magic(b"hsqs", "squashfs", "filesystem"),
    _Magic(b"sqsh", "squashfs", "filesystem"),
    _Magic(b"\x31\x18\x10\x06", "ubifs", "filesystem"),
    _Magic(b"\x1f\x8b\x08", "gzip", "compression"),
    _Magic(b"\xfd7zXZ\x00", "xz", "compression"),
    _Magic(b"\x04\x22\x4d\x18", "lz4-frame", "compression"),
    _Magic(b"\x28\xb5\x2f\xfd", "zstd", "compression"),
    _Magic(b"PK\x03\x04", "zip", "archive"),
    _Magic(b"PK\x05\x06", "zip", "archive"),
    *(_Magic(b"BZh" + bytes([digit]), "bzip2", "compression") for digit in range(49, 58)),
)
OVERLAP_BYTES = max(len(spec.magic) for spec in _MAGICS) - 1
HEADER_BYTES = 4096
_MACHINES = {
    3: ("x86", {32}),
    8: ("mips", {32, 64}),
    20: ("powerpc", {32}),
    21: ("powerpc64", {64}),
    40: ("arm", {32}),
    62: ("x86_64", {64}),
    183: ("aarch64", {64}),
    243: ("riscv", {32, 64}),
}


def scan_chunk(
    data: bytes, base_offset: int, new_start: int, limit: int
) -> tuple[list[Signature], bool]:
    """Find at most ``limit`` matches, retaining earliest offsets across patterns.

    ``data`` includes overlap from the previous chunk. Matches entirely before
    ``new_start`` have already been recorded. Per-pattern search counts are
    capped so repeated magic bytes cannot grow the result list without bound.
    """
    matches: list[Signature] = []
    for spec in _MAGICS:
        position = 0
        found = 0
        while found <= limit:
            position = data.find(spec.magic, position)
            if position < 0:
                break
            offset = base_offset + position
            if offset + len(spec.magic) > new_start:
                matches.append(Signature(spec.name, spec.category, offset))
                found += 1
            position += 1
    matches.sort(key=lambda match: (match.offset, match.name))
    return matches[:limit], len(matches) > limit


def header_signatures(header: bytes) -> list[Signature]:
    """Recognize signatures at documented fixed offsets in the outer image."""
    matches: list[Signature] = []
    if len(header) >= 263 and header[257:263] in (b"ustar\x00", b"ustar "):
        matches.append(Signature("tar", "archive", 257))
    if len(header) >= 1082 and header[1080:1082] == b"\x53\xef":
        matches.append(
            Signature("ext-family", "filesystem", 1080, evidence="ext superblock magic only")
        )
    # JFFS2's short magic is only checked at the outer header to reduce noise.
    if len(header) >= 12 and header[:2] in (b"\x85\x19", b"\x19\x85"):
        import zlib

        order = "little" if header[:2] == b"\x85\x19" else "big"
        length = int.from_bytes(header[4:8], order)
        crc = int.from_bytes(header[8:12], order)
        if length >= 12 and zlib.crc32(header[:8]) == crc:
            matches.append(
                Signature("jffs2", "filesystem", 0, evidence="node header magic and header CRC32")
            )
    return matches


def outer_format(header: bytes, matches: list[Signature]) -> str:
    """Describe the outer header without promoting embedded matches to containers."""
    if not header:
        return "empty"
    for match in matches:
        if match.offset == 0:
            return match.name
    fixed = header_signatures(header)
    if fixed:
        return fixed[0].name
    return "unknown"


def elf_architecture(header: bytes) -> tuple[Architecture | None, tuple[str, ...]]:
    """Read architecture only from a complete, internally consistent outer ELF header."""
    if not header.startswith(b"\x7fELF"):
        return None, ()
    if len(header) < 16:
        return None, ("elf_header_incomplete",)
    elf_class, encoding, version = header[4:7]
    if elf_class not in (1, 2) or encoding not in (1, 2) or version != 1:
        return None, ("elf_header_invalid",)
    bits = 32 if elf_class == 1 else 64
    required = 52 if bits == 32 else 64
    if len(header) < required:
        return None, ("elf_header_incomplete",)
    order = "little" if encoding == 1 else "big"
    ehsize_offset = 40 if bits == 32 else 52
    if (
        int.from_bytes(header[16:18], order) not in (1, 2, 3, 4)
        or int.from_bytes(header[20:24], order) != 1
        or int.from_bytes(header[ehsize_offset : ehsize_offset + 2], order) != required
    ):
        return None, ("elf_header_invalid",)
    machine = int.from_bytes(header[18:20], order)
    known = _MACHINES.get(machine)
    if known is None:
        return None, ("elf_machine_unrecognized",)
    name, classes = known
    if bits not in classes:
        return None, ("elf_header_inconsistent_architecture",)
    return Architecture(name, bits, order, machine), ()
