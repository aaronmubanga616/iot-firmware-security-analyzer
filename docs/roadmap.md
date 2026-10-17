# Development roadmap

Build one stage at a time. Document actual verification separately from planned
work; this roadmap is not a test result or a claim of implemented analysis.

1. **Foundation (implemented):** package layout, dependency-free help/version/about
   CLI, developer environment, synthetic-test policy, initial tests, GitHub
   Actions and safety documentation.
2. **Read-only firmware intake (implemented):** bounded regular-file input,
   streaming SHA-256, file size, raw signatures, consistent outer ELF metadata,
   JSON export and optional resource-limited Binwalk 3 identification. Synthetic
   tests cover empty, unknown, truncated, malformed, oversized, changed and
   unreadable inputs. Header observations do not prove image validity.
3. **Isolated extraction (next):** verify live installed Binwalk 3 behavior;
   design isolation, link/path containment, resource limits, timeouts and clear
   unsupported-format errors. Add synthetic hostile extraction fixtures before
   testing approved research images.
4. **Static inventory:** enumerate files, configurations, ELF metadata, package
   manifests and startup services with bounded reads and sanitized diagnostics.
5. **Candidate security rules:** add focused rules with stable identifiers,
   redacted evidence references, false-positive guidance and `unverified` status.
6. **Reporting:** define versioned JSON output and escaped HTML/Markdown reports
   with limitations, errors, evidence provenance and validation state.
7. **Manual research:** obtain approval to acquire OWASP IoTGoat, record provenance,
   perform manual Ghidra work and document isolated lab observations. Keep inputs
   and extracted material private and outside the repository.
8. **Publication:** review research notes for accuracy and sensitive information,
   add reproducible instructions, describe validation and disclose responsibly.

Use a descriptive Git commit for each reviewable stage. No stage automatically
authorizes downloads, network activity, privileged actions or exploitation.
