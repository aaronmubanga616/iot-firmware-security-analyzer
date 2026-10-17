# Safety model

## Current boundary

The foundation CLI only renders built-in help and project information. It does
not read firmware, extract files, execute external programs, access the network
or generate vulnerability findings. Installing development dependencies and
publishing to GitHub are separate, explicitly approved network operations.

## Requirements for later stages

All firmware and extracted content is untrusted, including names, terminal
control characters, links and third-party tool output. Apply explicit input,
output, time, memory, file-count and expanded-size limits appropriate to each
operation. A metadata-only workflow must not extract or execute anything.

Before extraction is implemented, design and test path containment, absolute
paths, parent traversal, symlinks, hard links, device nodes, special files and
decompression bombs. Avoid privileged execution. Run approved extraction helpers
in a disposable environment with restricted network access and bounded
resources. Extracted firmware binaries are never executed by static analysis.

Never include actual credentials, private keys or password hashes in logs or
reports. Future detectors should report presence and sanitized evidence
locations. Tests use artificial markers rather than actual secrets. Future
HTML reports must escape untrusted content; Markdown output must also handle
untrusted links, markup and control characters safely.

Every candidate starts as `unverified`. Static patterns alone do not establish
exploitability. Record what was observed, the limitations, and the human
validation needed. No automatic exploitation or contact with devices is allowed.

## Approval and publication

Obtain explicit approval for external downloads, network access, remote Git
operations and privileged actions. Document the target and purpose. A planned
download is not permission to fetch firmware or dependencies. Publishing the CI
workflow requires approval because hosted runners install dependencies.

Keep real firmware, extracted data and private lab notes outside Git. Ignored
local directories are convenient, but `.gitignore` does not protect files already
tracked or detect every secret. Review staged content and sanitize research notes
before publication. Only synthetic test material belongs in the repository.
