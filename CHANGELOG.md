# Changelog

Notable user-facing changes are documented here. This project follows Semantic Versioning.

## [Unreleased]

### Added

- Bounded ext4 depth-two extent-tree traversal with intermediate-index, leaf, and data-block provenance.
- Cross-level extent-index range validation and repeated/cyclic tree-block rejection under shared metadata-entry bounds.
- Bounded ext2/3 single-indirect-block mapping for active directories and regular files, including pointer-block and pointer-entry provenance.
- FAT16 BPB/fixed-root validation, deleted short/LFN inventory, and cautious recursive recovery through single-cluster or exact EOC-terminated FAT chains.
- Bounded active FAT16 subdirectory traversal with complete-chain gating and deleted-child directory lineage.

## [1.1.0] - 2026-09-04

### Added

- Bounded ext4 depth-one extent-tree traversal for root/subdirectories and active regular files.
- Exact extent-index, leaf-block, leaf-entry, and data-block provenance in observations and recursive recovery findings.

### Changed

- Ext inode mapping now shares one validator across root directories, active subdirectories, and regular files.
- Extent trees reject repeated leaf pointers, invalid index ranges, tree/data block aliasing, sparse mappings, uninitialized extents, deeper trees, and mappings outside filesystem/image/resource bounds.
- 283 deterministic synthetic regression tests are runnable without pytest.

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
