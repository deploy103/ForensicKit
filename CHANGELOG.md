# Changelog

Notable user-facing changes are documented here. This project follows Semantic Versioning.

## [1.0.0] - 2026-09-03

### Added

- Deterministic offline pipeline from evidence preservation through reporting.
- Signature identification, bounded native triage, profile/rule planning, and optional local tool execution.
- Recursive extraction with SHA-256 deduplication and depth/count/size limits.
- Provenance-preserving flag detection across common encodings and transforms.
- Coverage for images, archives, PCAP protocols, Windows artifacts, memory, mobile, and disk/filesystem evidence.
- SQLite case database, JSON/Markdown reports, CSV timeline, CLI, and read-only Textual TUI.
- Offline bundle tooling and first-class environment doctor.
- 282 deterministic synthetic regression tests runnable without pytest.

### Security

- Evidence is never executed; tools use argv arrays, isolated output directories, and timeouts.
- Runtime analysis makes no external API or network calls.
