# Firmware identification and metadata

This stage implements read-only metadata inspection. It does not extract files,
execute firmware, disassemble binaries or generate vulnerability findings.

## Usage

Reinstall the editable package after changing entry points, approving any build
dependency downloads first: `python -m pip install -e '.[dev]'`.

```sh
iotfw inspect firmware/sample.bin --output reports/metadata.json
iotfw inspect firmware/sample.bin --verbose
iotfw inspect firmware/sample.bin --max-size-mib 256 --timeout 30
iotfw inspect firmware/sample.bin --binwalk --output reports/binwalk-metadata.json
```

`iot-firmware-analyzer inspect` and `python -m iot_firmware_analyzer inspect`
provide the same behavior. Use the virtual environment's Python or console
executable when it is not activated. `iotfw inspect --help` lists the options.

Without `--output`, JSON goes to stdout. Logs go to stderr; `--verbose` adds
per-chunk progress and tool diagnostics. Input paths, firmware contents, tool
descriptions and raw exceptions are omitted from both logs and reports. Reports
identify the inspected bytes by size and SHA-256 rather than an input filename.

Missing report directories are created. An existing destination, including the
input itself or a link, is never overwritten. Choose a fresh report filename.
Reports are created with owner-only permissions where the operating system
supports POSIX modes; Windows permissions follow the parent directory's ACL.

Exit codes: 0 for successful built-in inspection (including a recorded optional
Binwalk failure), 1 for inspection/report failures, 2 for invalid arguments or
resource limits, and 130 for a user interruption during inspection.

## Built-in identification

The scanner hashes the entire accepted file in chunks and observes signatures
at exact byte offsets. It does not decompress input or trust its extension.
Matches may be incidental, embedded, incomplete or deliberately forged.
`image_format` describes an outer header observation, not a validated image.

| Family | Recognized evidence |
| --- | --- |
| ELF | Magic; additional complete header checks required for architecture |
| U-Boot legacy | Legacy image magic; architecture is not inferred |
| TRX | `HDR0` magic |
| Flattened device tree | FDT magic; does not establish that it is a FIT image |
| UBI / UBIFS | Respective image/node magic |
| SquashFS | Little/big endian filesystem magic |
| JFFS2 | Outer node magic and correct node header CRC32 |
| ext family | Magic at the outer superblock's expected position; ext2/3/4 are not distinguished |
| gzip / xz / bzip2 | Compression magic; bzip2 block-size marker checked |
| LZ4 frame / Zstandard | Frame magic |
| ZIP / tar | ZIP magic; tar's fixed-offset marker |

Generic signatures are searched throughout the raw file, including across read
boundaries. JFFS2, ext and tar use outer fixed-position checks. The scanner does
not search inside compressed data. Missing signatures do not establish absence.

Architecture is populated only for an outer ELF header with valid class, byte
order, ELF version, object type, header length and a recognized compatible machine
ID. It records the declared machine, ELF class and byte order. Supported machine
IDs cover x86, x86_64, ARM, AArch64, MIPS, PowerPC/PowerPC64 and RISC-V. This
describes that ELF object; it does not prove the target device's CPU architecture.
Embedded ELF signatures never become an image-wide architecture claim.

## Limits and input validation

- Default input maximum: 1 GiB; configurable from 1 MiB to 16 GiB in the CLI.
- Default processing budget: 60 seconds; configurable up to 600 seconds.
- Default chunk buffer: 1 MiB; library settings allow 4 KiB to 4 MiB.
- At most 256 built-in signatures by default; library settings allow 1–1024.
- Only regular files are accepted. Symbolic links, Windows reparse points,
  directories, special files and UNC/device paths are rejected.
- Input identity, byte count, size and modification indicators are checked
  before/after reading; detected changes invalidate the result.

The in-process time budget is cooperative between reads; it cannot interrupt a
blocked kernel filesystem operation. Metadata checks detect ordinary mutations,
but cannot guarantee an atomic snapshot against an adversarial concurrent writer
or eliminate every parent-directory race. Use a stable local file in a trusted
directory. File reads can update filesystem access times. Large inputs are not
loaded into memory. When the match cap is exceeded, hashing still covers the full
file and `signature_scan_complete` is false with `signature_limit_reached`.

## Optional Binwalk 3

`--binwalk` explicitly authorizes running the installed local tool, with no
installation or download. The adapter is Linux-only because it requires Linux
process resource limits. A missing tool, older major version, unsupported platform,
timeout, malformed output or parser failure is recorded in `binwalk.status` and
`binwalk.warnings`; built-in metadata remains available. Live integration with
an installed Binwalk is a separate verification from synthetic adapter tests.

The adapter uses a private temporary copy of the exact input bytes hashed. It
checks `binwalk --version`, then invokes an argument array equivalent to:

```sh
binwalk --quiet --threads 1 --log - -- /private/work/image.bin
```

The CLI flags and JSON envelope were checked against the official
[CLI parser](https://github.com/ReFirmLabs/binwalk/blob/master/src/cliparser.rs),
[JSON logger](https://github.com/ReFirmLabs/binwalk/blob/master/src/json.rs) and
[analysis result structure](https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk.rs).
No extraction, carving, recursion, entropy or external-helper flags are supplied.
Binwalk's signature parsers can perform internal validation and decompression;
the adapter is therefore a stronger resource boundary than the built-in matcher.

The input copy is capped at 64 MiB. Each child has a 512 MiB address-space limit,
a CPU budget based on the remaining deadline, a 1 MiB regular-file size limit,
no core dumps and at most 64 open descriptors. A fresh Python child sets limits
before executing the tool; no `shell=True` or pre-exec callback is used. Version
checking has at most 3 seconds, and the entire optional tool phase at most 20
seconds, further constrained by the remaining inspection budget. Combined
stdout/stderr is capped at 1 MiB and the process group is killed on termination.
The child's environment is reduced and its working directory is private.

These limits are not a complete operating-system sandbox or a network namespace.
Run only a trusted installed Binwalk in your authorized, isolated research lab.
Raw tool descriptions, paths and unknown free-text names are redacted. Known
signature identifiers are mapped to fixed names; other identifiers appear as
`other`. Tool matches do not change the built-in outer format or architecture.

## JSON schema 1.0

Each report contains `schema_version`, `tool`, `size_bytes`, `sha256`,
`image_format`, nullable `architecture`, `signatures`, `compression`,
`filesystems`, `signature_scan_complete`, `warnings`, `binwalk` and `limitations`.
Offsets are zero-based raw-file byte offsets. Each signature has a name,
category, source and evidence statement. Compression/filesystem lists summarize
both built-in and sanitized optional tool matches. Binwalk has its own status,
version, signatures and warnings. No device properties, vulnerabilities, secrets,
input contents or unsupported architecture guesses are invented.

## Verification record

Local verification on 2026-10-17 used Windows, Python 3.13.14 and pytest 9.1.1:
**127 passed, 8 skipped**. Skips cover four Linux child resource tests, three
symlink tests requiring unavailable Windows privileges and one POSIX FIFO test.
Both installed console commands and the module entry point produced JSON in
integration tests. The installed `iotfw inspect --help` command and dependency
consistency check also passed.

Binwalk is not installed in this environment. Adapter command/version/JSON/error
handling is verified with controlled responses; these are not live Binwalk or
real-firmware analysis results. Linux CI results must be read separately after
publication. The previous [foundation record](foundation.md) is historical.
