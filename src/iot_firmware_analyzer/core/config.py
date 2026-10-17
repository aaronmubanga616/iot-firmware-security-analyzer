"""Explicit resource limits for local, read-only firmware inspection."""

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class InspectionLimits:
    """Bound file reads, working memory, processing time and recorded matches."""

    max_file_bytes: int = 1024 * 1024 * 1024
    timeout_seconds: float = 60.0
    chunk_bytes: int = 1024 * 1024
    max_signatures: int = 256

    def __post_init__(self) -> None:
        """Reject invalid limits, including non-finite or excessive values."""
        for value, minimum, maximum in (
            (self.max_file_bytes, 1, 16 * 1024**3),
            (self.chunk_bytes, 4096, 4 * 1024**2),
            (self.max_signatures, 1, 1024),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("Inspection resource limit is outside its allowed range.")
        if (
            isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 600
        ):
            raise ValueError("Inspection timeout must be finite and at most 600 seconds.")
