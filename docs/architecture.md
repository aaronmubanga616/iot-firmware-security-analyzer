# Architecture

## Foundation decisions

Use a `src` layout so tests and commands exercise the installed package instead
of accidentally importing the checkout. Use `argparse` for a dependency-free CLI,
`setuptools` for packaging and `pytest` for tests. Python 3.11 is the minimum.
The package currently has no third-party runtime dependencies.

| Package | Responsibility | Current implementation |
| --- | --- | --- |
| `core` | CLI, future configuration and orchestration | Help, version, about |
| `firmware` | Format identification, metadata, hashes, extraction adapters | Package boundary only |
| `analysis` | Filesystem, ELF, package, configuration and startup inventories | Package boundary only |
| `security` | Detection rules and candidate finding models | Package boundary only |
| `reporting` | JSON schema and HTML/Markdown renderers | Package boundary only |

Both `iot-firmware-analyzer` and `python -m iot_firmware_analyzer` call the same
`core.cli.main` function. No firmware path is accepted yet. The default command
prints help. Parser errors use exit code 2. Tests exercise both installed entry
points without reaching the network or invoking firmware programs.

## Planned data flow

1. `core` checks user configuration, explicit approvals and local input limits.
2. `firmware` reads bounded headers and streams file hashing; later it delegates
   supported extraction to isolated, approved helper processes.
3. `analysis` produces inventories from a contained extraction directory.
4. `security` evaluates inventories and emits unverified candidates with
   sanitized evidence references, never secret values.
5. `reporting` serializes structured results and escapes all untrusted data for
   its output format. Reports describe limitations and validation status.

Analysis and security modules must not depend on rendering. Tool-specific
adapters must not become requirements for basic metadata analysis. External
tool failures should become clear, sanitized diagnostics, not fabricated data.

## Planned records and boundaries

Define typed records when implementing the features that use them: firmware
identity, inventories, analysis errors, candidate findings and report metadata.
Keep stable rule IDs, validation state and schema version explicit. Do not design
an unused abstraction hierarchy in the foundation.

Binwalk 3 will be an optional external identification/extraction adapter with
version checks and captured structured diagnostics. Its exact commands and
behavior must be verified against installed tools and approved official
documentation during implementation. Merely running Binwalk is not a sandbox.

Ghidra remains a manual research workflow. Sanitized notes may reference symbols,
offsets, hashes and the analyst's interpretation. Isolated laboratory observations
must be clearly distinguished from static observations and hypotheses.

## Testing

Unit tests cover parser behavior and project metadata. Integration tests launch
the installed console and module entry points. Later stages add tiny synthetic
firmware headers, hostile archive paths, resource limits, redaction cases and
report escaping. Tests must not require network, real targets, privileged
execution, Binwalk, Ghidra or execution of extracted programs.
