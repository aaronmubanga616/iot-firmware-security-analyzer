"""Linux child launcher: set hard resource limits before executing installed Binwalk.

This file is launched with Python's isolated mode. It is not a firmware entry
point, and accepts arguments constructed only by the Binwalk adapter.
"""

import os
import sys


def main() -> int:
    """Apply resource limits in a fresh process, avoiding unsafe preexec callbacks."""
    if sys.platform != "linux" or len(sys.argv) < 4:
        return 125
    import resource

    cpu_seconds = int(sys.argv[1])
    for kind, maximum in (
        (resource.RLIMIT_AS, 512 * 1024**2),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, 1024**2),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_NOFILE, 64),
    ):
        _, hard = resource.getrlimit(kind)
        value = maximum if hard == resource.RLIM_INFINITY else min(maximum, hard)
        resource.setrlimit(kind, (value, value))
    os.execve(sys.argv[2], sys.argv[2:], dict(os.environ))
    return 125


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        raise SystemExit(125) from None
