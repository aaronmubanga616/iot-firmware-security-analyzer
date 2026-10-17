# Contributing

Start with [README.md](README.md), [AGENTS.md](AGENTS.md) and the
[architecture](docs/architecture.md). Keep each contribution focused on one
roadmap stage and discuss substantial architecture changes before implementing
them.

1. Create a local Python environment using the README instructions. Approve any
   package downloads before running them through an assistant.
2. Implement a small, documented change with type hints and sensible failure
   behavior. Prefer standard-library dependencies.
3. Test implemented behavior with `python -m pytest` inside the environment.
   Use generated synthetic files; do not download firmware in tests.
4. Exercise affected installed CLI commands. Keep documentation aligned with
   actual capabilities and limitations.
5. Inspect staged changes for secrets, third-party research data and unintended
   files. Commit each completed stage with a descriptive message.

Do not execute extracted programs, automatically exploit candidates, or publish
sensitive firmware content. Follow [SECURITY.md](SECURITY.md) for security reports.
Avoid public issues containing actual credentials or unredacted device data.
