# IoT Firmware Reverse Engineering and Security Analyzer

A Python framework for static security research on legally acquired Linux router
and IoT firmware. OWASP IoTGoat is the planned initial research target.

**Status: metadata inspection / pre-alpha.** Inspect a local firmware file for
size, SHA-256, signature observations and reliable outer ELF architecture
metadata. Export structured JSON, with optional installed Binwalk 3 identification
on Linux. Extraction, inventories, security rules and HTML/Markdown remain planned.
No real firmware research or vulnerability findings are claimed.

```sh
iotfw inspect firmware/sample.bin --output reports/metadata.json
```

See [inspection usage, supported signatures and limitations](docs/inspection.md).

## Quick start

Use Python 3.11 or later. The core package has no third-party runtime dependencies.
Kali Linux is the intended research environment; this foundation also runs on
Windows. Installing dependencies downloads packages and requires approval when
working with an assistant. The commands below are instructions to run after
approving that activity.

Linux / Kali:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/iot-firmware-analyzer --help
.venv/bin/iot-firmware-analyzer --version
.venv/bin/iot-firmware-analyzer about
.venv/bin/iotfw inspect --help
.venv/bin/python -m pytest
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\iot-firmware-analyzer.exe --help
.\.venv\Scripts\iot-firmware-analyzer.exe --version
.\.venv\Scripts\iot-firmware-analyzer.exe about
.\.venv\Scripts\iotfw.exe inspect --help
.\.venv\Scripts\python.exe -m pytest
```

Activation is optional; these commands use the environment directly. After
installation, `python -m iot_firmware_analyzer --help` is also supported when
`python` refers to that environment. Run `iot-firmware-analyzer about --help`
for subcommand help. Running the CLI without arguments displays help and exits
successfully. Invalid arguments exit with code 2.

## Architecture

```text
src/iot_firmware_analyzer/
    __init__.py          Package version
    __main__.py          Python module entry point
    core/                CLI, limits, sanitized errors and orchestration
    firmware/            Streaming hashing, signatures, ELF metadata, Binwalk adapter
    analysis/            Future ELF, filesystem, package and service inventories
    security/            Future candidate findings and detection rules
    reporting/           JSON metadata export; future HTML and Markdown reports
tests/
    unit/                CLI and package behavior
    integration/         Installed entry points, local synthetic inputs
    fixtures/            Synthetic fixture policy; no real firmware
docs/                    Architecture, safety, roadmap and research templates
.github/workflows/       Automated installation and tests
```

`analysis` and `security` remain package boundaries for later stages. See
[architecture](docs/architecture.md) and the [development roadmap](docs/roadmap.md).
The [foundation record](docs/foundation.md) explains each created file and records
the actual local verification results.

## Research safeguards

- Analyze firmware you are authorized to possess and examine.
- Treat filenames, metadata, configurations and all extracted content as untrusted.
- Never execute extracted firmware binaries during static analysis.
- Never print or commit actual credentials, private keys or password hashes.
- Treat every future security finding as **unverified** until manually validated.
- Require explicit approval before downloads, network activity or privileged actions.
- Do not automatically exploit vulnerabilities or contact target devices.
- Keep firmware, extracted data, Ghidra projects and sensitive reports outside Git.

The current CLI reads regular firmware files without executing them. It performs
no network requests. Only `--binwalk` invokes an external parser, under Linux
resource limits, with no extraction flags. Reports omit input filenames, raw
contents and raw tool descriptions. `.gitignore` helps prevent accidental additions; review
every staged change because ignore patterns cannot identify every sensitive file.
See [the safety model](docs/safety.md) and [security reporting policy](SECURITY.md).

## Development and contribution

Use a dedicated environment and run `python -m pytest` before committing changes.
Add tests using synthetic data for each implemented capability. Keep work in
reviewable commits for each stage. Contributor and assistant instructions are in
[AGENTS.md](AGENTS.md); see [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

GitHub Actions is configured to install the package, exercise both CLI names and run tests
on Linux with Python 3.11–3.13 and Windows with Python 3.13. A configured workflow
is not evidence of a successful run; use the actual Actions results.

## Next stage

Design and test isolated extraction: containment, hostile paths and links,
expanded-size/file-count limits, timeouts and supported tool behavior. Metadata
intake and the optional signature-only Binwalk adapter are implemented. Inventories,
candidate findings, HTML/Markdown and manual Ghidra research follow separately.

Binwalk 3 and Ghidra are not required or automatically installed. IoTGoat
downloads must be separately approved; firmware and extracted content will not
be included in this repository.

## License

MIT; see [LICENSE](LICENSE). This license covers project code and documentation,
not third-party firmware or research material.
