# IoT Firmware Reverse Engineering and Security Analyzer

A Python framework for static security research on legally acquired Linux router
and IoT firmware. OWASP IoTGoat is the planned initial research target.

**Status: foundation / pre-alpha.** The installed CLI provides help, version and
project information. Firmware identification, extraction, detection rules and
report generation are planned; they are not implemented in this release. No
firmware has been analyzed and no vulnerability findings are claimed.

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
.venv/bin/python -m pytest
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\iot-firmware-analyzer.exe --help
.\.venv\Scripts\iot-firmware-analyzer.exe --version
.\.venv\Scripts\iot-firmware-analyzer.exe about
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
    core/                CLI; future configuration and orchestration
    firmware/            Future identification, metadata, hashing, extraction
    analysis/            Future ELF, filesystem, package and service inventories
    security/            Future candidate findings and detection rules
    reporting/           Future JSON, HTML and Markdown reports
tests/
    unit/                CLI and package behavior
    integration/         Installed entry points, local synthetic inputs
    fixtures/            Synthetic fixture policy; no real firmware
docs/                    Architecture, safety, roadmap and research templates
.github/workflows/       Automated installation and tests
```

Only `core` contains application behavior in this stage. The other subpackages
establish clear boundaries for later implementation. See
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

The current CLI performs no network requests and does not open firmware files or
invoke external tools. `.gitignore` helps prevent accidental additions; review
every staged change because ignore patterns cannot identify every sensitive file.
See [the safety model](docs/safety.md) and [security reporting policy](SECURITY.md).

## Development and contribution

Use a dedicated environment and run `python -m pytest` before committing changes.
Add tests using synthetic data for each implemented capability. Keep work in
reviewable commits for each stage. Contributor and assistant instructions are in
[AGENTS.md](AGENTS.md); see [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.

GitHub Actions is configured to install the package, exercise the CLI and run tests
on Linux with Python 3.11–3.13 and Windows with Python 3.13. A configured workflow
is not evidence of a successful run; use the actual Actions results.

## Next stage

Implement read-only firmware intake: bounded file inspection, size, SHA-256 and
conservative identification from header bytes. Test synthetic files, invalid
paths and resource limits before adding extraction. Binwalk 3 integration,
isolated extraction, inventories, candidate findings, reports and manual Ghidra
research follow in separate stages.

Binwalk 3 and Ghidra are not needed or installed by this foundation. IoTGoat
downloads must be separately approved; firmware and extracted content will not
be included in this repository.

## License

MIT; see [LICENSE](LICENSE). This license covers project code and documentation,
not third-party firmware or research material.
