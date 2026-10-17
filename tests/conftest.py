"""Small, generated firmware headers shared by metadata and CLI tests."""

from collections.abc import Callable
import struct

import pytest


@pytest.fixture
def make_elf() -> Callable[..., bytes]:
    """Construct an artificial complete ELF header without any program payload."""
    def build(machine: int = 40, bits: int = 32, order: str = "little") -> bytes:
        size = 52 if bits == 32 else 64
        header = bytearray(size)
        header[:7] = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1 if order == "little" else 2, 1))
        prefix = "<" if order == "little" else ">"
        struct.pack_into(prefix + "HHI", header, 16, 2, machine, 1)
        struct.pack_into(prefix + "H", header, 40 if bits == 32 else 52, size)
        return bytes(header)

    return build
