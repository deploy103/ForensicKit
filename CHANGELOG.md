# Changelog

Notable user-facing changes are documented here. This project follows Semantic Versioning.

## [Unreleased]

## [1.2.0] - 2026-09-09

### Added

- Installed-runtime `self-test` covering evidence preservation, bounded extraction, recursive decoding/flag discovery, lineage, investigation records, SQLite, and JSON/Markdown/HTML reports without external tools.
- Explicit hypothesis and verification records for every finding, including transactional SQLite persistence, legacy-case backfill, and report provenance.
- TUI artifact-tree, complete classification, and complete observation views with defensive partial/cyclic-lineage handling and keyboard navigation.
- Planner decisions now account for confidence, evidence size, expected value, CPU/RAM budgets, platform support, and prior tool/finding/observation prerequisites.
- Declarative rules can emit observations, confidence changes, and auditable parser/extractor actions, and can depend on previous findings and tool results.

- Fixed-path, bounded Amcache application/file inventory and Windows 8+ 00ts/10ts AppCompatCache parsing with Registry-cell/value byte provenance, raw timestamp semantics, common-search integration, and cautious findings.
- Exact normalized-path correlation across independently supplied Amcache, Shimcache, LNK, EVTX process, and browser records, without converting cache presence into an execution verdict.
- Threaded analysis sessions and an active Textual workflow for evidence/search input, Quick/Automatic/Deep/Plan runs, progressive results, cancellation, whole-request retry, filters/timezone display, candidate copy, and extracted-file saving.
- Offline bundle v2 component manifests recording source/wheel/deb/rule/catalog/prepared-tool/symbol versions, license metadata, supported environments, sizes, and hashes; prepared trees must be fully described and cannot contain links or special files.
- Offline installer v2 validation now parses metadata as data instead of sourcing bundle-controlled shell and refuses missing component inventory.
- Volatility commands now enforce offline quiet JSON execution and case-scoped output paths even for locally overridden templates; Doctor verifies the installed framework, 16 required plugins, and extraction arguments against the real CLI.
- Windows full-memory AUTO analysis now includes `windows.info.Info`, normalizes its OS/kernel fields, and exposes them with preserved tool-output provenance.
- Registry cache provenance now labels hive-relative and absolute hive-file offsets separately for Amcache keys/values and Shimcache entries.
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
- FAT32 subdirectory chain records now retain selected-FAT entry offsets/raw values; active subdirectory LFNs preserve either validated lineage or an explicit checksum/ordinal failure record.
- Deleted FAT32 LFN chains inside validated active subdirectories now use the same missing-short-byte checksum reconstruction and carry directory/FAT provenance into recursive recovery.
- Deleted FAT32 root cluster fields now preserve raw/masked values and reserved-high bits; malformed entries remain visible but cannot become recursive children.
- Failed active and deleted FAT12/16 LFN sequences inside validated subdirectories now retain exact slot/short-entry offsets, raw bytes, and complete containing-directory cluster lineage instead of being silently discarded.
- FAT32 unlinked-LFN provenance now produces a dedicated cautious profile finding and persists its exact directory/slot failure evidence in JSON and Markdown reports.
- FAT32 subdirectory LFN slots orphaned by an end marker or followed by an incompatible volume-label entry now remain visible with raw bytes and complete containing-directory provenance.
- Active LFN slots orphaned by a root-directory end marker are now retained consistently across FAT12/16/32 with exact absolute slot offsets and raw bytes.
- Active FAT12/16/32 root directory LFNs now undergo the same ordinal/checksum/UTF-16 validation as file LFNs; valid names enrich subdirectory inventory while failures remain unlinked evidence.
- Nested active FAT12/16/32 directory LFNs now enrich their exact queued inventory records, while invalid chains retain the containing directory source and cluster lineage.
- Nested active/deleted FAT12/16/32 file records and recursive recovery findings now retain their immediate containing directory's short name, validated LFN, LFN slot offsets, source entry, and cluster lineage without fabricating a full path.
- Deeper FAT file records now carry a bounded ordered directory-identity lineage, with per-level short/LFN names, source offsets, LFN slots, and start clusters kept distinct from any inferred path string.
- FAT12/16/32 boot sectors now receive variant-specific BPB relationship validation covering jump/marker structure, geometry, mutually exclusive size fields, root/FAT layout, cluster-count class, and FAT32 version/reserved bytes; malformed structures produce provenance-rich profile findings.
- FAT volumes with missing or misleading informational type labels are now classified by fully validated BPB cluster-count geometry and FAT entry capacity; label fields, raw offsets, the selected basis, and any disagreement remain explicit provenance.
- Primary MBR entries now drive bounded exact-offset FAT/NTFS/exFAT boot-sector validation, including independent partition-type, embedded start-LBA, and declared-size comparisons with anomaly findings and no mounting.
- CRC-validated GPT entries now receive the same exact-offset boot checks with GUID/name provenance; the declared backup header/table is independently CRC-checked and compared without selecting or repairing a copy.
- Extended MBR partitions now receive bounded EBR-chain traversal with distinct current-EBR logical offsets and extended-base link offsets, cycle/bounds isolation, and exact-offset logical FAT/NTFS/exFAT boot validation.
- Complete small partitions with structurally valid table entries and boot sectors can now become immutable child artifacts under extraction limits, recursively activating the existing filesystem parsers and FlagHunter with exact source-observation and byte-range lineage.
- Primary MBR, EBR logical, and CRC-eligible GPT data extents now receive bounded cross-table duplicate/overlap analysis; every competing entry retains exact range provenance and is barred from recursive copying, while extended/protective MBR containers are inventoried but excluded from expected-containment conflicts.
- Portable ASCII `odc` and SVR4 CPIO `newc`/CRC archives now receive bounded native format-specific entry/trailer/path/checksum inventory and regular-file extraction with exact byte-range provenance; links, special files, and unsafe names remain metadata-only.
- ISO 9660 images now receive bounded descriptor/PVD/root and active-subdirectory parsing with both-endian, block-boundary, dot/dotdot, and shared/cyclic-extent validation; safe single-extent files can recursively re-enter analysis with exact descriptor, record, byte-range, archive-path, and directory-identity lineage.
- Valid root-self SUSP markers now enable bounded inline Rock Ridge parsing: safe continuation-aware `NM` names and `PX` POSIX metadata enrich ISO lineage, while malformed/unsafe metadata, `SL` symlinks, and POSIX special files remain raw evidence and cannot be materialized.
- Joliet level 1-3 supplementary descriptors and bounded UCS-2BE directory trees are validated independently; exact unique primary/Joliet file extents provide alternate path provenance without duplicate child extraction.
- El Torito boot records and default catalogs now receive validation checksum/key, media, load-RBA, and byte-range checks; only deterministic ISO-bounded initial boot-load extents can recursively re-enter analysis with raw catalog provenance.
- El Torito final/chained section headers, platform boot entries, and parent-linked extension criteria are parsed under 8-KiB/64-slot bounds; deterministic section load extents retain validation/header/entry provenance during recursion.
- Primary ISO Type-L/Type-M path-table copies now receive bounded framing, hash, parent/path, endian-independent comparison, and exact active-directory reconciliation; divergent copies remain non-authoritative anomaly evidence.
- Rock Ridge `CE` continuation areas now resolve under global byte/count/depth and overlap bounds; continued names retain exact source/hash provenance and are revalidated before extraction, while cycles or partial continuations remain metadata-only.
- Rock Ridge short/long `TF` timestamps now retain raw offsets and normalized UTC, while both-endian `PN` device numbers are reported without ever materializing device nodes.
- Rock Ridge `CL`/`PL`/`RE` relocation roles and target blocks are validated and reconciled to known directory extents, but remain deliberately non-traversing metadata to avoid inferred paths and cycles.
- Adjacent ISO 9660 multi-extent regular-file records can now form one bounded child after identifier/version, non-final alignment, range, overlap, terminator, and per-record provenance validation; primary/Joliet aliases require the same ordered extent sequence, while incomplete or over-limit chains remain wholly metadata-only.
- Active Joliet descriptors now drive bounded Type-L/Type-M path-table parsing with strict UCS-2BE names, per-copy hashes, cross-endian semantic comparison, and exact active-tree reconciliation; divergent copies remain non-authoritative anomaly evidence.
- Valid Rock Ridge `PX` serial/link-count claims now form evidence-only hard-link groups only when their exact ordered extent identities agree; one canonical payload is copied while alternate paths remain provenance, and contradictory groups are never reconciled or materialized as host links.
- El Torito hard-disk-emulation default and section entries now receive exact 512-byte MBR signature/partition/range/overlap validation with raw/hash provenance and a minimum covered length; full image size remains deliberately indeterminate and no speculative child is created.
- Rock Ridge `ZF` claims now drive metadata-only zisofs header and block-pointer validation under decompressed-size, 65,536-pointer, and 1-MiB metadata bounds; exact offsets, hashes, compressed ranges, and zero-fill blocks are retained without decompression or speculative child creation.
- Fully validated single-extent zisofs streams can now become recursive children after the extractor independently revalidates raw ZF/header/table provenance and decodes every zlib block to its exact bounded size; corrupt, trailing, over-expanding, or partially decoded streams are deleted without registration.
- Nonzero ISO directory-record extended-attribute lengths now receive bounded ECMA-119 field/range/hash validation. Single-extent and every multi-extent file-section XAR are independently reread before data copying; multi-extent record format/attributes and fixed-record lengths must be consistent, and record-oriented files require valid XARs on every section.
- Primary and Joliet path-table XAR block counts now retain bounded range provenance and must match the exact XAR length/data start of their uniquely sampled active-directory record; the directory XAR verdict/hash is attached after parsing without making a path table authoritative.
- Old binary CPIO archives are now detected and parsed in canonical big- or byte-swapped little-endian form, preserving 26-byte word/header/range provenance; safe regular files are recursively extracted only after the entire binary header and metadata are independently revalidated.
- Validated CPIO trailers can now delimit multiple bounded concatenated archives; fixed-size zero-padding scans require an aligned recognized next header, retain per-archive format/byte-order/range lineage, and never resynchronize after corruption.
- CPIO regular-file hard links are now reconciled within each archive/device/inode only when link counts and inode metadata agree and exactly one member carries data. That canonical payload is copied once after every group header is reread; aliases, contradictions, and host-link creation remain suppressed with explicit provenance.
- Bounded CPIO symlink payloads now retain exact bytes, SHA-256, strict UTF-8 target text, and traversal-safety metadata in findings and reports without following or creating links.
- Pure and ISO-hybrid UDF images now receive bounded BEA/NSR/TEA recognition, multi-block-size anchor discovery, exact descriptor-tag checksum/CRC/location and CRC-coverage validation, partition/LVD parsing, main/reserve VDS body/semantic comparison, and Type-1 resolution of an exact FSD plus root FE/EFE.
- Root FE/EFE short or long allocation descriptors now drive an 8-MiB/4,096-record metadata-only FID inventory with exact extent segments, tag location/checksum/CRC, aligned implementation-use/padding, safe CS0 names, ICB ranges, and a unique self-referential root parent record; child ICBs and content remain untraversed.
- Active root FIDs now drive deduplicated exact child FE/EFE rereads, full variable CRC-coverage and file-type relationship checks, and bounded structural short/long/extended/embedded allocation-descriptor metadata. File data is never read or materialized at this stage.
- Validated directory child ICBs now drive a breadth-first UDF tree inventory under shared 32-directory, 8-MiB, and 4,096-FID caps, with exact parent relationships/component lineage plus shared/cyclic ICB and cross-directory extent-overlap rejection; deleted FIDs remain non-traversing metadata.
- Unique active UDF regular files backed wholly by recorded-allocated Type-1 short/long extents can now recurse after a full preserved-source hash, fresh stored-tree equality, per-file raw FID/ICB/AD rereads, metadata/cross-file overlap rejection, and exact `informationLength` copying without allocation slack.
- Complete UDF short/long AD files may now combine recorded data with allocated or unallocated sparse logical-zero ranges, and embedded-in-ICB regular files may recurse from exact revalidated FE/EFE bytes; transformed and alias layouts remain suppressed.
- Extended UDF ADs now preserve separate allocation, recorded, and information lengths per ECMA-167. Equal recorded/information bytes and exact sparse zeros may recurse through Type-1 maps; length-divergent compression evidence remains structurally valid metadata but is never decoded or copied as plaintext.
- UDF short/long/extended allocation arrays now resolve bounded Type-1 Allocation Extent Descriptor chains with exact tag/checksum/CRC/location/previous-pointer/range/hash provenance and cycle/overlap defenses. Only complete chains are eligible, and every AED is immutably reread before extraction; malformed or incomplete chains remain metadata-only.

### Changed

- Textual is now a standard runtime dependency so the required no-subcommand keyboard interface is present after an ordinary installation.
- Offline release bundles require clean Git provenance by default, record the exact commit/dirty state and reproducible wheel epoch, exclude stale build products, validate archives, lock one immutable wheel per resolved Python distribution, and include standalone verified installer helpers.
- The release gate now binds a bundle to the exact gated Git commit/source archive and canonical project-wheel checksum instead of accepting an older clean bundle.
- Offline installation is staged and self-tested before activation; upgrades force-reinstall the checksummed wheel, refuse unrelated or protected prefixes, authenticate recognized prior ForensicKit layouts with a path-bound marker, and restore the prior prefix after activation failures.
- Findings now begin with an honest `unverified` verification placeholder even when supporting evidence strings are present; `supported` requires an explicit method, conclusion, source, and verification evidence.
- Planner history deduplicates an exact tool/mode/parameter execution rather than suppressing legitimate follow-up modes, and rule confidence/parser/extractor actions now have bounded, persisted execution semantics.
- External-tool outputs are accepted only after bounded count, aggregate-byte, per-file, link/special-file, partial-run, and case-scope audits; live growth past the aggregate limit terminates the tool.
- README is now a detailed Korean competition operator guide covering architecture, stack, evidence coverage, tool/bootstrap installation, offline media, CLI/TUI, reports, safety limits, troubleshooting, and real-environment gates.
- Doctor and operational health commands provide machine-readable JSON output, while routine CLI evidence/workspace errors return concise non-traceback failures.

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
