# Changelog

Notable user-facing changes are documented here. This project follows Semantic Versioning.

## [Unreleased]

### Added

- Bounded ext4 depth-two extent-tree traversal with intermediate-index, leaf, and data-block provenance.
- Cross-level extent-index range validation and repeated/cyclic tree-block rejection under shared metadata-entry bounds.
- Bounded ext2/3 single-indirect-block mapping for active directories and regular files, including pointer-block and pointer-entry provenance.
- FAT16 BPB/fixed-root validation, deleted short/LFN inventory, and cautious recursive recovery through single-cluster or exact EOC-terminated FAT chains.
- Bounded active FAT16 subdirectory traversal with complete-chain gating and deleted-child directory lineage.
- Strict FAT12 fixed-root classification, deleted-entry inventory, and recursive recovery through direct or correctly packed exact-EOC chains.
- Bounded active FAT12 subdirectory traversal with packed-chain provenance, shared-cluster protection, and deleted-child recursion.
- FAT32 FSInfo, backup boot, and backup FSInfo validation with range-checked hints and exact divergence offsets.
- Bounded FAT12/16 duplicate allocation-table comparison with exact relative/absolute first-divergence and truncated-copy provenance, without authoritative-copy selection.
- FAT32 duplicate FAT comparison now honors BPB ExtFlags mirroring and active-table selection, including active-copy chain traversal and non-verdict inactive-copy divergence.
- Per-copy FAT12/16/32 reserved-entry validation now cross-checks the BPB media descriptor and preserves FAT16/32 clean-shutdown and hard-error status bits.
- Bounded FAT12/16/32 allocation scans now inventory complete, fragmentary, cross-linked, and cyclic chain components absent from the validated active-directory reference sample.
- Complete image-bounded FAT lost chains can now become anonymous, full-cluster child artifacts for recursive signature and flag analysis with explicit unknown-size/slack and ownership caveats.
- Active FAT12/16 root and subdirectory files now preserve validated intact LFNs and recurse only through exact size-required chains ending at EOC.
- Active FAT32 root/subdirectory file recovery now masks 28-bit directory clusters and follows only the BPB ExtFlags-selected FAT; deleted multicluster recovery uses the same selected table.

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
