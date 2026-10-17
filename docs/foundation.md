# Foundation delivery record

Date: 2026-10-17. The initial project directory was empty and was not a Git
repository. No pre-existing project files required preservation. A local virtual
environment was created in `.venv`; its contents are ignored by Git.

## Files and responsibilities

| File or group | Purpose |
| --- | --- |
| [`pyproject.toml`](../pyproject.toml) | Build configuration, Python minimum, metadata, MIT license declaration, editable installation, console entry point, pytest extra and test settings |
| [`.gitignore`](../.gitignore) | Excludes environments, caches, build products, research images, extracted data, private reports and common secret/key files |
| [`.gitattributes`](../.gitattributes) | Normalizes text line endings and marks common media formats as binary |
| [`LICENSE`](../LICENSE) | MIT license for project code and documentation |
| [`README.md`](../README.md) | Project scope, environment commands for Kali/Linux and Windows, architecture, safeguards and next stage |
| [`AGENTS.md`](../AGENTS.md) | Persistent contributor/assistant rules for approvals, untrusted inputs, secrets, testing and stage commits |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Contribution and verification workflow |
| [`SECURITY.md`](../SECURITY.md) | Project security reporting guidance and responsible treatment of firmware findings |
| [`src/iot_firmware_analyzer/__init__.py`](../src/iot_firmware_analyzer/__init__.py) | Exposes the installed distribution version |
| [`src/iot_firmware_analyzer/__main__.py`](../src/iot_firmware_analyzer/__main__.py) | Supports the Python module entry point |
| [`src/iot_firmware_analyzer/py.typed`](../src/iot_firmware_analyzer/py.typed) | Marks the distributed package as typed |
| [`src/iot_firmware_analyzer/core/__init__.py`](../src/iot_firmware_analyzer/core/__init__.py) | Declares the application orchestration boundary |
| [`src/iot_firmware_analyzer/core/cli.py`](../src/iot_firmware_analyzer/core/cli.py) | Implements help, version and about; rejected arguments are not echoed |
| [`firmware/__init__.py`](../src/iot_firmware_analyzer/firmware/__init__.py) | Establishes the future identification, metadata, hashing and extraction package |
| [`analysis/__init__.py`](../src/iot_firmware_analyzer/analysis/__init__.py) | Establishes the future inventory package |
| [`security/__init__.py`](../src/iot_firmware_analyzer/security/__init__.py) | Establishes the future rule and unverified-candidate package |
| [`reporting/__init__.py`](../src/iot_firmware_analyzer/reporting/__init__.py) | Establishes the future JSON/HTML/Markdown reporting package |
| [`tests/unit/test_cli.py`](../tests/unit/test_cli.py) | Tests default help, explicit help, version, project status, invalid commands and argument redaction |
| [`tests/integration/test_entrypoints.py`](../tests/integration/test_entrypoints.py) | Runs both installed entry points outside the checkout and rejects a generated synthetic firmware file without modification |
| [`tests/fixtures/README.md`](../tests/fixtures/README.md) | Synthetic-only fixture policy |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Installation and tests on Linux/Python 3.11–3.13 and Windows/Python 3.13, with read-only repository permissions |
| [`docs/architecture.md`](architecture.md) | Module responsibilities, planned data flow and integration boundaries |
| [`docs/safety.md`](safety.md) | Current behavior and requirements for future extraction, redaction and publication |
| [`docs/roadmap.md`](roadmap.md) | Incremental implementation stages and acceptance expectations |
| [`docs/research/README.md`](research/README.md) | Policy for sanitized research notes |
| [`docs/research/note-template.md`](research/note-template.md) | Blank provenance, Ghidra, laboratory and candidate validation template |
| [`docs/foundation.md`](foundation.md) | This file inventory and actual foundation verification record |

The four analysis-related package boundaries contain only docstrings. They do
not yet implement firmware processing, detection or reporting.

## Actual local verification

- Environment: Windows, Python 3.13.14, pytest 9.1.1.
- Editable installation with the development extra completed successfully.
- `python -m pytest --tb=short`: **27 passed** (15 unit, 12 integration).
- `python -m pip check`: **No broken requirements found.**
- Installed console `--help` and `--version` commands completed successfully.
- Installed module `about` command completed successfully.
- Project TOML parsed and all 10 Python source/test files passed syntax checks.
- Ignore rules were checked for the virtual environment, local configuration,
  firmware, extracted data and private reports; the fixture README remains visible.

The initial sandboxed test run passed 15 unit cases but could not create temporary
directories for 12 integration cases. The explicitly approved run outside that
sandbox passed all 27 tests. This was an environment restriction, not evidence
that firmware analysis had occurred.

The CI matrix is configured. These local checks do not establish results on Kali,
Python 3.11/3.12 or hosted GitHub runners. Read the actual Actions results after
publication. No real firmware was downloaded, extracted, analyzed or executed;
no vulnerability findings were generated.

## Next development step

Implement read-only intake with regular-file validation, streaming SHA-256,
file size and bounded format-header observations. Define typed metadata results
and explicit resource limits. Add synthetic malformed-input and error-path tests.
Keep extraction, rules and report rendering in later stages.
