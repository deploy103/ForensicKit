# ForensicKit Work Log

## 2026-09-04 21:53 KST

### FAT16 fixed-root inventory and deleted-file recursion

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `src/forensickit/profiles/disk.py`, and `tests/test_engine_pipeline.py`.
- FAT16 activation now requires its BPB label plus valid sector/cluster/FAT/fixed-root geometry, a cluster count in the FAT16 range, and enough 16-bit FAT entries for the declared clusters. The bounded fixed root retains exact entry offsets, timestamps, low cluster, reserved high word, raw bytes, and validated deleted-LFN provenance.
- Regular deleted entries with a zero FAT16 reserved high word may recurse from one image-bounded cluster. Multi-cluster files require at most 64 unique, in-range 16-bit FAT pointers and EOC immediately after the size-required final cluster; current allocation is always labeled as a reuse-prone recovery candidate rather than ownership proof.
- Added Engine coverage for deleted LFN recovery to `Very Long Flag.txt`, direct `CTF{fat16_fixed_root}`, noncontiguous `6 → 8 → EOC` recovery of `CTF{fat16_multicluster}`, reserved-high-word exclusion, FAT12-sized geometry rejection, and withholding a chain that does not terminate at EOC.
- Verified `python -m compileall -q src tests scripts`, the 40 Engine regressions, and the full direct suite (**286 passed, 0 failed**); `git diff --check` remained clean.

### Next

- Traverse bounded active FAT16 subdirectories and retain directory source/cluster lineage on deleted children before invoking the same recovery checks.

## 2026-09-04 21:41 KST

### ext2/3 single-indirect directory and file mapping

- Changed `src/forensickit/triage.py` and `tests/test_triage.py`, then updated disk-profile/recovery wording and capability/limitation records.
- Active directories and regular files may now use all 12 direct pointers plus one bounded single-indirect pointer block. The mapper validates pointer capacity, filesystem/image bounds, complete declared coverage, unique data blocks, and metadata/data non-aliasing before any bytes are parsed or recovered.
- Mapping provenance retains the inode's indirect-pointer offset, pointer-block physical block/byte offset, required pointer count/capacity, every pointer index/byte offset, and the resulting logical/physical data segment.
- Added one image that maps both a 13-block root directory and a 13-block regular file, recursively recovers `CTF{ext_single_indirect}`, and rejects an indirect pointer that aliases an already accepted direct data block.
- Verified `python -m compileall -q src tests scripts` and focused triage regressions (**85 passed, 0 failed**).
- Full post-release direct regression passed (**285 passed, 0 failed**); `git diff --check` remained clean.

### Next

- Add bounded FAT16 fixed-root directory inventory and cautious deleted single-cluster regular-file recovery with LFN provenance.

## 2026-09-04 21:38 KST

### Bounded ext4 depth-two extent-tree traversal

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py` after the v1.1.0 tag.
- Generalized the shared ext mapper to traverse at most two external index levels. Every child header must decrease depth exactly once; index keys stay inside their parent's logical range; tree blocks are image-bounded and globally unique per inode; total index/leaf entries remain under the existing 64-block recovery bound.
- Observations and recovery findings now retain root and intermediate index-entry offsets, parent index linkage, index-block headers, leaf headers/entries, and final data offsets. Initialized data extents cannot alias any tree block or another physical data interval.
- Added a full depth-two root-directory and regular-file fixture plus recursive Engine recovery of `CTF{ext4_depth_two_tree}`. A self-referencing intermediate index is rejected before any directory bytes are trusted.
- Verified `python -m compileall -q src tests scripts` and focused triage regressions (**84 passed, 0 failed**).

### Next

- Add bounded ext2/3 single-indirect-block mapping with exact pointer-block provenance and data/metadata alias rejection.

## 2026-09-04 21:16 KST

### v1.1.0 publication

- Created release commit `b9810d391b2e402f186ba12ac1f36fac9392afdb` (`release: ForensicKit v1.1.0`) and annotated tag `v1.1.0`; pushed both to `origin`.
- Published the non-draft, non-prerelease GitHub release at `https://github.com/deploy103/ForensicKit/releases/tag/v1.1.0`.
- Authoritative release inspection confirmed uploaded assets `forensickit-1.1.0-py3-none-any.whl` (264,363 bytes) and `SHA256SUMS` (101 bytes), both in `uploaded` state.
- Downloaded both published assets into an isolated `/tmp` audit directory. The remote checksum manifest validated the remote wheel as `0b6781a26c26759105b64f4222699cec3d7dbf4cf5465dcdb4da64fe882fa74a`, and byte comparison matched both local release artifacts exactly.

## 2026-09-04 20:55 KST

### ext4 depth-one extent-tree traversal and recursive recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- Replaced three divergent ext mapping paths with one bounded validator for ext2/3 direct blocks and ext4 depth-zero/depth-one trees. Depth-one indices must be strictly ordered and point to unique image-bounded leaves; leaf headers, logical ownership ranges, initialized extents, tree/data non-aliasing, complete logical coverage, and existing byte/block limits all validate before use.
- Root directories, active subdirectories, and regular files retain exact index-entry, leaf-block/header/entry, and final data-block provenance. The extractor revalidates read segments independently and carries the full tree provenance into its finding before recursive child analysis.
- Added a synthetic depth-one root/file image proving native directory parsing, child recovery, `CTF{ext4_depth_one_leaf}` lineage, and rejection of a repeated leaf pointer.
- Verified `python -m compileall -q src tests scripts`, focused triage regression (**83 passed, 0 failed**), and the full direct suite (**283 passed, 0 failed**).

### v1.1.0 release validation

- Bumped package/runtime/help/README metadata to `1.1.0`, added the changelog and release notes, and built `dist/forensickit-1.1.0-py3-none-any.whl` without dependency or network resolution.
- Verified wheel metadata and bundled YAML resources, then installed it with `--no-index --no-deps` into an isolated Python 3.12 environment. The installed package reported `1.1.0`, CLI help rendered, and `forensickit doctor` exited 0 while accurately distinguishing present and missing optional tools.
- A full release rerun exposed a scheduler-dependent test assumption: a 0.1-second timeout could expire before the fixture's shebang-launched Python wrote its flushed marker. The output-preservation subcase now allows 1 second against a 30-second sleep; production timeout behavior is unchanged. The 16 tool-runner tests passed three consecutive runs afterward.
- Re-ran the full direct suite after the version bump (**283 passed, 0 failed**), re-ran compileall, validated the release artifact structure, and verified final SHA-256 `0b6781a26c26759105b64f4222699cec3d7dbf4cf5465dcdb4da64fe882fa74a` against `SHA256SUMS`.
- Release gate is ready for the `release: ForensicKit v1.1.0` commit and annotated `v1.1.0` tag.

## 2026-09-03 13:30 KST

### Active ext subdirectory traversal and nested-file recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_workspace_extraction.py`.
- Added reusable bounded ext inode loading, initialized depth-zero extent/direct-block mapping, and feature-aware directory-record parsing. Breadth-first traversal accepts only allocated directory inodes reached from validated active entries and shares a 32-directory/64-block/8-MiB budget.
- Root and descendant directory inode numbers and physical blocks are deduplicated. Repeated inodes, root/ancestor/shared blocks, malformed records, zero-link directories, unsupported indirect/extent-tree mappings, sparse/uninitialized ranges, and filesystem/image-bound failures are recorded and never traversed.
- Descendant regular files retain their containing path, directory inode/source entry, complete inode ancestry, directory-block lineage, own inode offset, and logical/physical data segments. They enter the existing bounded extractor and recursive FlagHunter path without weakening independent segment/budget checks.
- The ext4 fixture now contains `/sub/inner.txt` through directory inode 13/block 9 and file inode 14/block 10, plus inode 15 attempting to reuse directory block 9. The valid child is mapped with `[2, 13]` ancestry while the shared-block directory is rejected; the workspace extraction fixture verifies nested-directory provenance.
- Verified `python -m compileall -q src tests`, focused triage/workspace/Engine regressions (**135 passed, 0 failed**), the shared-block fixture, and the full direct suite (**279 passed, 0 failed**).

### Stop state

- Continuous development was paused at the user's request. No command or edit remains in progress. Resume from the P0 recorded in `WORK_QUEUE.md`.

## 2026-09-03 13:55 KST

### Active ext root regular-file recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `tests/test_triage.py`, `tests/test_workspace_extraction.py`, and `tests/test_engine_pipeline.py`.
- Up to 128 active root entries now resolve their inode group/descriptor/table offsets. Recovery candidates require an allocated regular-file inode with a nonzero link count, at most 8 MiB/64 blocks, and complete image/filesystem-bounded initialized depth-zero extents or ext2/3 direct blocks. Sparse gaps, indirect blocks, extent trees, uninitialized extents, deleted inodes, and incomplete mappings are excluded with recorded errors.
- The extractor independently revalidates logical segment continuity, declared size, image bounds, and case budgets before copying exact bytes. Child findings retain directory-entry/inode offsets, inode mode/flags/link count, mapping mode, and every logical/physical segment.
- ext4 extent and ext2 direct fixtures map inode 12 to `flag.txt`; a workspace test proves child bytes and provenance. Full Engine AUTO E2E registers the child, preserves parent lineage, and finds `CTF{ext_engine_lineage}` on the child artifact.
- Focused regressions passed (**134 passed, 0 failed**), the standalone Engine E2E passed, and the full direct suite passed (**279 passed, 0 failed**).

### Next

- Generalize the validated ext directory/inode mapper into bounded breadth-first active-subdirectory traversal with shared inode/block protection, then feed complete regular-file mappings into the same recursive extractor with containing-directory lineage.

## 2026-09-03 13:45 KST

### Bounded ext root inode and directory inventory

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- Native ext analysis now validates group-zero descriptor placement, inode size/table bounds, allocated directory mode for inode 2, and a 1-MiB/64-block root size ceiling. ext4 depth-zero mappings require a valid extent header, initialized nonoverlapping extents, complete logical coverage, and filesystem/image-bounded physical blocks; ext2/3 mappings accept at most 12 complete direct pointers and never guess indirect blocks.
- Active directory records require block-local aligned record lengths and bounded names. Inode, raw/decoded name, feature-aware legacy/ext4 file type, logical offset, and exact physical offset are retained. Malformed entries terminate only their block and are recorded without fabricating membership.
- Synthetic ext4 extent and ext2 direct-pointer volumes both recover `.`, `..`, and `flag.txt` at exact offsets. The legacy test verifies 16-bit name lengths without the FILETYPE incompat feature.
- Focused regressions passed (**120 passed, 0 failed**) and the full direct suite passed (**277 passed, 0 failed**).

### Next

- Resolve bounded active regular-file inodes referenced by validated ext root entries, accept only complete initialized depth-zero extent or direct-block mappings, register children, and recurse into flags with exact inode/data-block provenance.

## 2026-09-03 13:36 KST

### exFAT main and backup boot-region validation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- When 24 complete sectors exist, the main and backup 12-sector regions are independently checked for the exFAT rotate checksum, one checksum value repeated across the full checksum sector, boot signature, all eight extended-boot signatures, and zero reserved sector. Extended boot code is informational and may be nonzero.
- The first 11 sectors are compared byte-for-byte while excluding only mutable VolumeFlags and PercentInUse bytes. Exact relative/main/backup offsets and differing bytes are retained; separately valid checksums do not cause either divergent copy to be declared authoritative.
- Truncated synthetic images preserve existing root analysis and record why boot-region validation is unavailable. A complete 40-sector fixture proves valid but divergent copies and rejection of one altered repeated checksum word.
- Focused triage/extraction/Engine regressions passed (**132 passed, 0 failed**) and the full direct suite passed (**276 passed, 0 failed**).

### Next

- Parse bounded ext2/3/4 group-zero descriptor and root inode mappings, then inventory structurally valid active root directory entries with exact inode/block/byte provenance.

## 2026-09-03 13:26 KST

### Active exFAT subdirectory traversal and deleted-child recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_workspace_extraction.py`.
- Active directory file sets must pass native entry-set checksum, exact stream/name sequencing, reserved stream-flag, UTF-16/padding, ValidDataLength/DataLength, volume/image, and allocation validation. NoFatChain extents are complete contiguous mappings; FAT directories require exactly the declared clusters and immediate EOC.
- Breadth-first traversal shares 32-directory/64-cluster/8-MiB limits and visited start/data clusters with root/system allocations, rejecting loops and shared clusters. Deleted directories are recorded as deleted sets but are never traversal sources.
- Deleted regular files inside validated directories retain containing-directory source offset and physical cluster lineage, enter the existing bounded content extractor, and remain recursive children with flag provenance. Output names now include physical entry offsets to avoid collisions between equal directory-local indices.
- Synthetic fixtures cover a NoFatChain directory and a noncontiguous `3 → 5 → EOC` directory, exact later-cluster offsets, a shared-cluster child rejection, and non-traversal of a deleted directory containing a fake entry. Focused regressions passed (**131 passed, 0 failed**) and the full direct suite passed (**275 passed, 0 failed**).

### Next

- Validate complete exFAT main and backup boot regions, including extended-sector signatures, repeated checksum sectors, exact divergence offsets, and safe behavior for truncated evidence.

## 2026-09-03 13:12 KST

### exFAT allocation bitmap and upcase-table validation

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_workspace_extraction.py`.
- Root system entries now retain exact offsets and validate reserved fields, active-FAT bitmap selection, exact bitmap length, unused high bits, and exact-EOC FAT mappings under 64-cluster/8-MiB/image/volume/FAT bounds. The parser records allocated counts and whether root/bitmap/upcase system clusters are themselves marked allocated.
- A bounded upcase table is trusted only when its exact-EOC mapping, stored rotate checksum, compressed runs, and complete 65,536 UTF-16 code-unit expansion validate. Only then is each deleted stream's stored name hash recomputed; absence or invalidity continues to be reported without a false validation claim.
- Candidate clusters for bounded NoFatChain and exact-EOC FAT streams are correlated with the validated active bitmap. A set bit produces an explicit current-allocation/reuse finding and lower-confidence provenance warning, but never proves ownership and never blocks cautious recovery.
- A synthetic volume validates system entry offsets/chains, a compressed ASCII upcase mapping, filename hash, system allocation consistency, and a currently allocated deleted cluster. Focused triage/extraction/Engine regressions passed (**129 passed, 0 failed**) and the full direct suite passed (**273 passed, 0 failed**).

### Next

- Traverse active exFAT subdirectory file sets under shared 32-directory/64-cluster/8-MiB bounds, supporting validated NoFatChain and FAT allocations while rejecting loops/shared clusters and never traversing deleted directories.

## 2026-09-03 13:02 KST

### Deleted exFAT FAT-chain content recovery

- Changed `src/forensickit/extraction.py` and `tests/test_workspace_extraction.py`.
- Deleted regular-file streams without NoFatChain now require exactly the cluster count implied by DataLength, a non-looping FAT mapping within declared FAT/volume/image bounds, and EOC immediately after the final required cluster. Early EOC, free/reserved/bad values, loops, and chains longer than the declared content are rejected.
- Recovery preserves every noncontiguous cluster/physical segment, reads evidence only through ValidDataLength, zero-fills the logical tail through DataLength, and retains the deleted-cluster reuse caveat before normal child registration and recursive flag analysis.
- A synthetic `3 → 5 → EOC` stream recovers `CTF{exfat_fat_chain}` and proves segment provenance. Focused regressions passed (**128 passed, 0 failed**) and the full direct suite passed (**272 passed, 0 failed**).

### Next

- Parse and validate active exFAT allocation-bitmap and upcase-table root metadata, revalidate stored name hashes when the bounded table is trustworthy, and treat current allocation bits only as reuse warnings for deleted streams.

## 2026-09-03 12:52 KST

### Bounded exFAT root FAT-chain traversal

- Changed `src/forensickit/triage.py` and `tests/test_triage.py`.
- exFAT root parsing now follows its FAT chain under 64-cluster/8-MiB, visited-loop, declared volume cluster, FAT byte, image byte, truncated-read, free/reserved/bad, and EOC checks. It retains each root cluster/physical offset/length and the exact termination/truncation state.
- Directory entry sets are parsed across the concatenated logical chain but every primary/secondary entry keeps its actual physical offset, including sets in noncontiguous or later clusters.
- The deleted-set fixture now uses `2 → 5 → EOC`; cluster 2 contains no end marker, while the valid deleted set is found only at cluster 5 offsets 2,560/2,592/2,624. Identification/checksum/profile coverage remains green.
- Verified focused exFAT/disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**271 passed, 0 failed**).

### Next

- Recover deleted exFAT streams without NoFatChain only when an exact non-looping FAT chain supplies the DataLength-required clusters and the final required cluster points to EOC, with ValidDataLength tail zero fill and physical-segment provenance.

## 2026-09-03 12:49 KST

### Deleted exFAT NoFatChain content recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, and `tests/test_workspace_extraction.py`.
- exFAT triage now retains sector/cluster/heap/count geometry needed for deterministic content mapping. The extractor accepts only checksum-validated inactive regular-file sets whose stream flags explicitly contain NoFatChain, with nonzero DataLength bounded to 8 MiB/64 clusters and a complete contiguous allocation inside the declared volume cluster range and evidence.
- Only bytes through ValidDataLength are read from evidence; the logical tail through DataLength is zero-filled so stale uninitialized allocation is never exposed. Ordinary depth/count/single/cumulative limits, hashing, deduplication, read-only child registration, and recursive analysis remain active.
- Provenance retains the complete entry set, checksum, stream flags, starting/count/physical cluster range, data/valid lengths, explicit zero-fill range, and deleted-cluster reuse caveat. A fixture with stale `X` bytes after a flag proves the tail is zero-filled and the flag remains discoverable.
- Verified focused exFAT/triage/extraction/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**271 passed, 0 failed**).

### Next

- Follow the exFAT root directory FAT chain under loop/value/FAT/image and 64-cluster/8-MiB bounds so complete inactive entry sets after the first root cluster retain exact physical entry offsets.

## 2026-09-03 12:46 KST

### exFAT identification and deleted root file sets

- Changed `src/forensickit/triage.py`, `src/forensickit/identification.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- exFAT is now identified from the offset-3 `EXFAT` OEM signature and classified as a filesystem/disk artifact. Native triage validates sector/cluster shifts, FAT/heap/root geometry, cluster/image bounds, and reads one at-most-2-MiB root cluster.
- An inactive primary `0x05` becomes a deleted file-set candidate only with 2..18 complete secondary entries, exactly one inactive stream `0x40`, the exact number of inactive name entries `0x41`, bounded 1..255 UTF-16 characters, zero padding, and a stored set checksum that validates after restoring deletion-cleared InUse bits.
- Results retain every entry offset, stored/restored checksum, attributes, stream flags, stored name hash, valid/data lengths, and starting cluster. Name hash is explicitly `not_verified_without_upcase_table`; no false validation is claimed without parsing that table.
- A synthetic deleted `deleted.txt` set verifies restored checksum, offsets, stream metadata, identification, and profile finding.
- Verified focused identification/disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**270 passed, 0 failed**).

### Next

- Promote only deleted exFAT regular streams carrying the NoFatChain flag when their complete declared contiguous cluster range is image-bounded and case extraction budgets pass; retain allocation-reuse caveats and recurse into recovered content.

## 2026-09-03 12:41 KST

### FAT32 active-subdirectory deleted-file recursion

- Changed `src/forensickit/extraction.py` and `tests/test_engine_pipeline.py`.
- Deleted regular-file metadata from validated active subdirectories now enters the same bounded FAT content-recovery path as root entries. Single-cluster/direct and multi-cluster/exact-EOC rules, image/FAT bounds, loop/value rejection, size/count/depth/cumulative budgets, deduplication, read-only registration, and reuse caveats are unchanged.
- Child finding evidence additionally retains containing-directory start cluster, complete directory cluster lineage, and the active directory's source-entry offset alongside the deleted entry and content-chain physical offsets.
- The combined Engine fixture now recovers a child from active directory cluster 3 and content cluster 4, finds `CTF{fat32_subdirectory_child}` recursively, and verifies directory source offset 1,120 and deleted entry offset 1,536.
- Verified focused extraction/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**269 passed, 0 failed**).

### Next

- Add exFAT boot identification and parse a strictly bounded root directory chain for inactive file-entry sets, requiring a complete stream extension/name sequence and preserving the stored set checksum before any recovery.

## 2026-09-03 12:39 KST

### Bounded FAT32 active-subdirectory deleted-entry inventory

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- Native FAT32 triage now queues only active directory entries from the validated root/descendant data. It recursively follows their FAT chains under shared 32-directory, 64-cluster, and 8-MiB bounds with visited start/data-cluster sets, FAT/image bounds, and EOC/invalid/loop termination provenance.
- Deleted regular/directory metadata inside fully read active-directory clusters retains the directory start, complete cluster lineage, parent directory source-entry offset, exact physical child-entry offset, short name, attributes, starting cluster, size, and raw bytes. `.`/`..`, invalid chains, and deleted directory entries are never traversal sources because their allocation is ambiguous.
- A synthetic root with active cluster-5 and deleted cluster-6 directories proves only cluster 5 is visited and its deleted `?HILD.TXT` is found at physical offset 2,560; fake deleted content under cluster 6 remains absent.
- Verified focused disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**269 passed, 0 failed**).

### Next

- Feed deleted regular-file entries from validated active subdirectories into the existing bounded FAT content extractor, retaining containing-directory cluster/source offsets in child provenance and preserving all chain/EOC checks.

## 2026-09-03 12:36 KST

### Complete multi-cluster FAT32 deleted-file recovery

- Changed `src/forensickit/extraction.py` and `tests/test_engine_pipeline.py`.
- Deleted regular files up to 8 MiB/64 clusters may now be recovered beyond one cluster only when declared size determines an exact required cluster count, every 28-bit FAT entry and cluster maps inside FAT/evidence bounds, the chain is non-looping and avoids free/reserved/bad/early-EOC values, and the final required cluster points directly to EOC.
- Physical segments may be noncontiguous. Only the declared byte count is copied, and the existing recursion/count/single/cumulative limits, deduplication, read-only child registration, flag scan, reuse caveat, entry provenance, and raw metadata remain active. A chain longer than declared content is rejected rather than silently truncated.
- The Engine fixture now recovers a noncontiguous `6 → 8 → EOC` 600-byte file whose flag exists only in the second cluster. A same-size `7 → 9 → 10` chain is withheld because it does not end at EOC after the final required cluster.
- Verified focused extraction/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**268 passed, 0 failed**).

### Next

- Inventory deleted entries inside bounds-validated FAT32 subdirectory chains with a global directory/cluster cap, visited cluster identities, parent directory cluster provenance, and no implicit traversal of deleted directory content when its allocation is ambiguous.

## 2026-09-03 12:28 KST

### Single-cluster deleted FAT32 content recovery

- Changed `src/forensickit/extraction.py` and `tests/test_engine_pipeline.py`.
- The built-in extractor promotes a deleted FAT32 regular file only when `0 < declared size <= cluster size`, its starting cluster's complete physical range lies inside evidence, directory/volume-label bits are absent, and ordinary depth/count/single/cumulative byte budgets all pass.
- Only declared bytes are copied from immutable evidence. Child/finding provenance retains entry index/offset/raw bytes, chosen validated LFN or reconstructed/unknown short name, starting cluster, physical offset, size, attributes, and an explicit `unknown_deleted_cluster_may_be_reused` allocation state; confidence is limited to 0.72.
- An Engine AUTO fixture recovers a Base64 flag solely from the deleted cluster, verifies recursive child/report lineage, and proves a 513-byte entry is not promoted from a 512-byte cluster.
- Verified focused extraction/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**268 passed, 0 failed**).

### Next

- For larger deleted files, require a complete non-looping FAT chain with exactly enough mapped clusters, no free/reserved/bad values, every range inside evidence, a 64-cluster/8-MiB cap, and EOC after the final required cluster before recursive promotion.

## 2026-09-03 12:24 KST

### Bounded FAT32 root-chain traversal

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- Root-directory parsing now follows validated 28-bit FAT32 entries for at most 64 clusters and 8 MiB. Every cluster and FAT entry must lie inside its respective image/FAT bounds; a visited set and explicit EOC, loop, free, bad, reserved, truncated-read, image/FAT-bound, and limit termination states prevent unbounded traversal.
- Directory entries are parsed from the concatenated logical chain but retain a per-entry physical-offset map and per-cluster `{cluster,offset,length}` provenance, including LFN slots crossing noncontiguous clusters. Fully read entries survive a later chain error; abnormal termination produces a cautious completeness finding.
- A synthetic `2 → 5 → 2` chain verifies noncontiguous cluster offsets, recovery of a deleted file entry from cluster 5, and deterministic loop termination before rereading cluster 2.
- Verified focused disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**267 passed, 0 failed**).

### Next

- Promote a deleted regular FAT32 entry only when its entire declared file fits one mapped cluster inside evidence and all case extraction budgets pass; retain directory-entry and physical-cluster provenance plus an explicit possible-reallocation caveat.

## 2026-09-03 12:21 KST

### Deleted FAT32 LFN chain correlation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- Contiguous LFN slots preceding a deleted short entry now validate attributes/type/zero-cluster fields, common checksum, at-most-20-slot/255-character bounds, physical or stored ordinal order, UTF-16, terminator/`0xFFFF` padding, and forbidden filename characters before producing a long name.
- When deletion destroys every ordinal byte as `0xE5`, physical slot order is explicitly labeled inferred. The missing short-name first byte is tested over exactly 256 values and must have one checksum solution; FAT's stored `0x05` representation is handled. Valid results retain long/reconstructed short names, checksum, slot indices/offsets, order/terminal modes, and recovered first byte.
- Mixed/bad checksums, invalid slots, ambiguous checksum recovery, oversized chains, dangling deleted slots, and deleted slots followed by an active short entry remain separate `unlinked_lfn_slots` evidence rather than being attached. A two-slot `Very Long Flag.txt` fixture plus inconsistent-checksum negative verifies both paths.
- Verified focused disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**266 passed, 0 failed**).

### Next

- Follow the FAT32 root directory's FAT chain with a strict cluster cap, visited set, reserved/bad/EOC handling, FAT/image bounds, and per-cluster provenance so deleted entries beyond the first cluster can be inventoried safely.

## 2026-09-03 12:16 KST

### FAT32 root deleted short-entry recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- FAT32 boot geometry now maps exactly one complete root-directory cluster after validating sector/cluster size, reserved sectors, FAT count/size, root cluster, cluster read bound (2 MiB), image bounds, and entry cap (1,024 examined/256 deleted).
- Deleted non-LFN 32-byte entries retain exact directory offset/index, raw bytes, `?` for the irrecoverable first 8.3 character, remaining short name, attributes, high/low starting cluster, size, and validated creation/access/write FAT timestamps. No FAT chain or content is followed.
- The Disk profile emits an information-level recovery lead explicitly describing the metadata-only scope. A synthetic FAT32 image verifies `?LAG.TXT`, offset 1,024, cluster 5, size 123, raw entry bytes, and subsecond creation time.
- Verified focused disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**265 passed, 0 failed**).

### Next

- Preserve preceding deleted FAT32 LFN slots and correlate them to a deleted short entry only when slot order, terminal marker, UTF-16 bounds, and short-name checksum validate; keep mismatches as unlinked metadata.

## 2026-09-03 12:13 KST

### NTFS backup boot-sector comparison

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- For an NTFS artifact with valid sector geometry and at least two sectors, native triage reads exactly the primary and final evidence sector. It separately records the backup offset, NTFS OEM signature, `0x55AA` marker, primary/backup validity, comparison result, and first differing byte.
- Content comparison and the medium consistency finding occur only when both 512-byte boot records have valid signatures/end markers. Missing or unrelated final-sector data is recorded as unavailable/invalid rather than called divergence.
- A synthetic valid backup with one changed volume-serial byte verifies the exact final-sector offset and first difference at byte 72.
- Verified focused disk/triage/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**264 passed, 0 failed**).

### Next

- Parse one bounds-validated FAT32 root-directory cluster for deleted 8.3 entries, retaining unknown first-character semantics, directory byte offset, starting cluster, size, attributes, and timestamps without following an unvalidated FAT chain.

## 2026-09-03 12:09 KST

### Independent NTFS `$MFTMirr` record-zero validation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`.
- Native NTFS triage reads record zero at the boot-declared mirror LCN only when its complete, at-most-4-KiB range lies inside evidence. The mirror independently validates FILE signature, used/allocated/attribute bounds, USA count and sector trailers before any comparison.
- Only when primary and mirror are independently valid are their USA-fixed logical bytes and allocated sizes compared. Observations retain exact mirror offset, all structural results, match state, and first logical difference; the Disk profile emits a medium-severity consistency finding only for two valid divergent records.
- The first focused sweep exposed an iterator API mistake that caused the isolated Disk profile to fail and seven downstream tests to lose its results. This was corrected before acceptance; all 136 affected focused tests passed.
- The first full sweep had one unrelated 0.01-second timeout fixture terminate before its initial stdout flush. Its 16-test module passed immediately in isolation, and a clean full rerun passed **263 tests, 0 failed**. The transient run is not counted as success.

### Next

- Read the final-sector NTFS backup boot record within sector/image bounds, validate its signature/end marker and compare it to the primary boot sector without treating an absent backup as a divergence.

## 2026-09-03 12:01 KST

### USN_RECORD_V4 range tracking

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, `src/forensickit/reporting.py`, and `tests/test_triage.py`.
- The lineage-gated journal parser now recognizes the distinct 64-byte USN_RECORD_V4 header. It validates record alignment, extent size, record-contained extent count (maximum 256), and nonnegative lengths, then preserves exact 128-bit file/parent IDs, USN, reason/source info, remaining extents, and signed offset/length ranges.
- V4 does not contain V2/V3 filename, timestamp, security ID, or file-attribute fields, so none are fabricated. Windows-profile language and timeline columns explicitly expose the version-appropriate range metadata.
- A synthetic two-extent V4 record verifies identifiers/layout, range offsets/lengths, reason decoding, and absence of name/time fields.
- Verified focused triage/report/profile regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**262 passed, 0 failed**).

### Next

- Independently read the boot-declared `$MFTMirr` record zero, apply its own bounds/USA validation, and compare validated primary/mirror logical record bytes with exact offsets.

## 2026-09-03 11:58 KST

### Ancestor-MFT provenance in USN timeline rows

- Changed `src/forensickit/reporting.py` and `tests/test_workspace_extraction.py`.
- Timeline generation now joins `correlation.usn_sampled_mft` back to a journal row only by the exact journal artifact, USN, and stream offset. Matching rows retain ancestor artifact ID/name, MFT observation ID, sampled FILE names/deletion state, and physical MFT segments.
- Both the triage and correlator sources/observation IDs remain visible. JSON retains structured names/segments, CSV receives dedicated fields under existing serialization safety, and Markdown shows the exact MFT context inline.
- A report fixture verifies identity, dual-source provenance, ancestor fields, physical offset, and the pre-existing USN formula-safety/UTC behavior.
- Verified focused reporting/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**261 passed, 0 failed**).

### Next

- Add bounded USN_RECORD_V4 parsing for range-tracking metadata and fixed-size extent arrays while keeping its absence of filename/timestamp semantics explicit.

## 2026-09-03 11:54 KST

### USN to ancestor sampled-MFT correlation

- Changed `src/forensickit/engine.py` and `tests/test_workspace_extraction.py`.
- Case correlation now follows a journal child's recorded parent chain (cycle-safe, maximum 16 ancestors) to the nearest artifact with sampled MFT records. A V2 event links only to a signature/bounds/USA-valid FILE record whose 48-bit record number and 16-bit sequence both match exactly.
- Reciprocal journal/image observations and a finding retain both artifact IDs, both source observation IDs, USN/stream offset/time/reasons, journal and sampled names as context, deletion state, and physical MFT segments. Filename equality is not a match key; a same-FRN different-sequence event is excluded as possible record reuse.
- A workspace fixture verifies the positive chain, intentionally different context names, physical provenance, and sequence-mismatch negative.
- Verified focused workspace/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**261 passed, 0 failed**).

### Next

- Fold exact MFT correlations into matching USN timeline rows so CSV/JSON/Markdown review preserves the ancestor artifact and physical FILE-record source without consulting raw observation tables.

## 2026-09-03 11:50 KST

### USN_RECORD_V3 and 128-bit identifiers

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, `src/forensickit/reporting.py`, `tests/test_triage.py`, and `tests/test_workspace_extraction.py`.
- The bounded lineage-gated journal parser now distinguishes V2's 60-byte and V3's 76-byte layouts. V3 128-bit file and parent IDs are preserved as exact raw hex values and are never coerced into V2's 48-bit MFT record/16-bit sequence representation.
- Timeline rows identify each actual USN record version and include dedicated 128-bit ID columns. Windows findings describe version-appropriate identifiers. V2 rename pairing now explicitly requires integer V2 FRN/sequence fields, preventing absent V3 fields from matching as `None` values.
- Synthetic V3 coverage verifies exact IDs, layout offsets, delete reason, USN, filename, and absence of a fabricated V2 file-record number.
- Verified focused triage/report/profile regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**260 passed, 0 failed**).

### Next

- Link V2 journal records back to a parent/ancestor image's bounded sampled MFT record only when both file record number and sequence match exactly, preserving both observation and artifact chains.

## 2026-09-03 11:46 KST

### Exact USN rename correlation

- Changed `src/forensickit/profiles/windows.py` and `tests/test_rules_profiles.py`.
- The Windows profile pairs rename-old/new records only when they are adjacent in captured journal order, the file record and sequence match exactly, and the new USN equals the old USN plus its full record length. Same-name/time proximity is never sufficient.
- Each pair preserves both names, both parent record/sequence references, both timestamps, both USNs, and both exact stream offsets. It becomes a normalized observation plus an information finding without inferring a full path or user intent.
- A synthetic sequence proves one exact pair is retained while an adjacent record with a mismatched file sequence is excluded.
- Verified focused Windows-profile/triage regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**259 passed, 0 failed**).

### Next

- Parse aligned USN_RECORD_V3 entries with their 128-bit file/parent identifiers as exact opaque values; do not coerce them into V2 MFT record/sequence semantics.

## 2026-09-03 11:43 KST

### USN report timeline integration

- Changed `src/forensickit/reporting.py` and `tests/test_workspace_extraction.py`.
- `report.json`, `report.md`, and `timeline.csv` now include normalized `$UsnJrnl:$J` records alongside EVTX events. Journal rows preserve USN, reason mask/names, file and parent record/sequence, filename, attributes, source info, security ID, record offset/length, source observation, artifact lineage, original timestamp, and normalized UTC.
- Markdown uses an explicit USN/FRN identity instead of presenting journal events as EVTX. CSV formula protection applies to USN filenames only during serialization; database/JSON evidence remains unchanged.
- A synthetic report fixture verifies +09:00→UTC normalization, journal columns, observation provenance, and formula-like filename safety.
- Verified focused report/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**258 passed, 0 failed**).

### Next

- Pair rename-old and rename-new USN events only when FRN/sequence agree and journal ordering is adjacent enough to remain explainable; preserve both names and offsets.

## 2026-09-03 11:40 KST

### Recovered NTFS `$UsnJrnl:$J` parsing

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, and `tests/test_triage.py`.
- Generic triage invokes the journal parser only when the artifact lineage name ends exactly in `$UsnJrnl:$J`; arbitrary unknown binaries are not treated as journals. It scans at most the first and last 8 MiB and retains at most 10,000 aligned USN_RECORD_V2 structures.
- Every record validates version, aligned record length, bounded UTF-16 filename location, and preserves exact stream offset/length, file and parent MFT record/sequence, signed USN, FILETIME, decoded reason bits plus raw mask, source info, security ID, attributes, and filename. No path or active/deleted state is inferred.
- The Windows profile activates on this evidence and produces a cautious inventory finding. A synthetic record verifies timestamps, combined create/rename/close reasons, IDs, offsets, and profile evidence.
- Verified focused triage/profile/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**257 passed, 0 failed**).

### Next

- Export journal records into the deterministic report timeline while preserving USN-specific identifiers/reasons and CSV formula safety.

## 2026-09-03 11:35 KST

### Exact sampled NTFS `$DATA` extent joining

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `tests/test_triage.py`, and `tests/test_workspace_extraction.py`.
- Data-run parsing now begins at each nonresident attribute's declared `lowest_vcn`. A base stream is joined to sampled extension records only when its resident `$ATTRIBUTE_LIST` contains an exact base entry and each extension entry agrees on type/name, target record/sequence, target attribute ID/lowest VCN, extension FILE base record/sequence, attribute flags, extent VCN continuity, and the existing 64-run bound.
- Joined descriptors preserve every contributing MFT record, sequence, attribute/VCN range, and physical MFT-record segment. They then use the same image-bound, allocation, logical-zero, recursion, count, size, SHA-256 deduplication, and provenance checks as ordinary nonresident recovery; partial component streams are not promoted.
- Synthetic join tests include a wrong base-sequence negative. A two-record extraction fixture proves both physical extents form exactly one child, retains extension-record evidence, and finds a flag located only in the second extent.
- Verified focused triage/workspace/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**256 passed, 0 failed**).

### Next

- Recognize recursively recovered `$UsnJrnl:$J` streams by lineage name and parse bounded USN_RECORD_V2 entries without scanning arbitrary unknown binaries as journals.

## 2026-09-03 11:30 KST

### Bounded NTFS INDX slack-entry leads

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- After a mapped INDX buffer passes signature, USA, active-header, terminal-entry, and allocation-bound validation, native triage scans only its declared unused allocation bytes on 8-byte boundaries. Candidates must have a bounded aligned entry, only recognized flags, a complete FILE_NAME key, a nonempty clean name, and a valid namespace.
- Slack candidates remain separate from active index entries and therefore do not participate in active index-to-MFT correlation. They carry an explicit `slack_candidate`, confidence 0.72, slack offset, record/sequence reference, buffer VCN/logical offset, and physical image segments; the profile describes them only as possible stale/deleted entries.
- Synthetic helper and full-image fixtures recover `deleted.doc`/`old-name.txt` from bounded slack without disturbing active entries or malformed-buffer isolation.
- Verified focused triage/profile regressions, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**253 passed, 0 failed**).

### Next

- Join sampled nonresident `$DATA` extents only when resident `$ATTRIBUTE_LIST` entries, target record sequence, extension-record base reference, attribute ID/name, and VCN continuity all agree.

## 2026-09-03 11:27 KST

### Nonresident NTFS `$I30` INDX parsing

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- NTFS boot parsing now retains the signed clusters-per-index-record result. Sampled directory records map at most 64/1 MiB of complete, non-sparse, uncompressed, unencrypted `$I30` INDEX_ALLOCATION buffers through validated runs.
- Each INDX buffer independently validates signature, physical image bounds, USA count/sector trailers, index-header allocation bounds, entry/key/subnode bounds, and FILE_NAME structure. Normal entries retain record/sequence, buffer VCN/logical offset, attribute/entry offsets, and every physical segment; later malformed buffers do not discard earlier valid evidence.
- Nonresident entries participate in the existing bounded index-to-sampled-FILE correlation and receive a distinct profile finding. Synthetic helper and full NTFS-image fixtures cover successful two-sector fixup, physical provenance, unresolved MFT reference, and malformed-buffer isolation.
- Verified focused triage/profile regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**253 passed, 0 failed**).

### Next

- Scan only bounded unused bytes inside already validated INDX allocation bounds for structurally plausible stale entries, label them deleted/slack candidates, and keep them separate from active index references.

## 2026-09-03 11:21 KST

### NTFS sparse and uninitialized nonresident recovery

- Changed `src/forensickit/extraction.py` and `tests/test_workspace_extraction.py`.
- Complete VCN-zero `$DATA`/ADS mappings may now contain sparse runs. Compression and encryption remain rejected; VCN continuity, highest VCN, physical image bounds, physical allocation size, real size, initialized size, run count, recursion depth, artifact count, and real-size extraction budgets all validate before output creation.
- Initialized allocated bytes are copied from immutable evidence, sparse logical ranges are zero-filled, and every byte after `initialized_size` through `real_size` is zero-filled without reading stale clusters. Per-range provenance distinguishes physical `{vcn,lcn,physical_offset,logical_offset,length}`, sparse `sparse_run`, and `uninitialized_tail` segments.
- A synthetic middle-sparse-run fixture proves exact 1,300-byte reconstruction, uninitialized physical-tail suppression, recursive flag discovery, and rejection of a gapped VCN mapping. The existing compressed-attribute negative fixture remains green.
- Verified focused workspace/Engine regressions, `python -m compileall -q src tests`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**251 passed, 0 failed**).

### Next

- Parse bounded nonresident `$I30` INDEX_ALLOCATION buffers only after physical mapping, INDX bounds, and USA fixup validation; retain directory-entry and buffer provenance.

## 2026-09-03 11:09 KST

### Expanded bounded NTFS MFT sampling

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, and `tests/test_engine_pipeline.py`.
- Native MFT sampling and resident/nonresident recovery now inspect at most 256 records instead of 32. Because record size remains capped at 4 KiB, mapped MFT reads remain bounded to 1 MiB; all existing USA, attribute, run, extraction byte/count, and recursion limits remain active.
- A synthetic MFT with invalid records 1–39 and a valid record 40 proves isolated structural failures do not hide later evidence. Record 40's `late.txt` resident data became a child and yielded its Base64 FlagCandidate.
- Verified focused triage/Engine tests, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**250 passed, 0 failed**).

### Next

- Reconstruct bounded sparse/uninitialized nonresident ranges with logical zero filling, while continuing to reject compressed/encrypted attributes and preserving per-run provenance.

## 2026-09-03 11:05 KST

### Sampled NTFS nonresident `$DATA` recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `tests/test_triage.py`, and `tests/test_engine_pipeline.py`.
- Sampled records now retain nonresident DATA attribute flags, VCN range, allocated/real/initialized sizes, and validated run descriptors. The extractor accepts only lowest-VCN zero, contiguous complete run coverage with every LCN inside the immutable image; compressed, encrypted, sparse, extension-only, partially initialized, oversized, and incomplete mappings are withheld.
- Physical ranges are read only up to real size, rechecked against recursion/extraction budgets, and registered with child/record/attribute/stream/deletion/run provenance. A deleted named nonresident stream yielded its own recursive FlagCandidate, while a same-record compressed stream remained unpromoted.
- Verified focused triage/Engine tests, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**249 passed, 0 failed**).

### Next

- Expand the safe MFT sample to 256 records (bounded to 1 MiB at the current 4 KiB maximum record size) and prove later-record resident/nonresident recovery.

## 2026-09-03 10:59 KST

### Sampled NTFS resident `$DATA` and ADS recovery

- Changed `src/forensickit/triage.py`, `src/forensickit/extraction.py`, `tests/test_triage.py`, and `tests/test_engine_pipeline.py`.
- The bounded 32-record MFT sampler now preserves resident `$DATA` only after FILE signature, record bounds, USA fixup, attribute length, and resident value bounds all validate. The extractor decodes those fixed in-memory bytes, reapplies case depth/count/single/cumulative-size and SHA-256 deduplication limits, and registers ordinary streams plus `filename:stream` ADS children.
- Each recovery finding retains child ID, record/attribute IDs, named/unnamed stream, deletion state, resident value offset, and logical-to-physical MFT record segments. A deleted `gone.txt` Base64 child and `gone.txt:ads` raw Flag child both re-entered recursive analysis with distinct provenance.
- Verified focused triage/Engine tests, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**249 passed, 0 failed**).

### Next

- Recover sampled NTFS nonresident `$DATA` only for complete VCN-zero, uncompressed, unencrypted, non-sparse run coverage within case byte limits.

## 2026-09-03 10:54 KST

### EVTX process to Registry persistence-value correlation

- Changed `src/forensickit/engine.py` and `tests/test_engine_pipeline.py`.
- The case correlator boundedly extracts only drive-absolute or UNC executable/script paths from already validated Registry execution-value strings. Relative names and strings containing unresolved `%ENV%` expansions are rejected; no Registry path, command, or environment variable is executed or resolved.
- An exact canonical full-path match to EVTX process creation creates reciprocal artifact observations with key/value/type/data, EventRecordID/native offset, both source observations, and exact supplied LOG1/LOG2 companion metadata. The finding explicitly avoids inferring the Registry value creation time.
- Verified focused database/provenance tests, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**247 passed, 0 failed**).

### Next

- Recover bounded resident NTFS `$DATA` from structurally valid sampled MFT records and promote each stream with record/attribute/deletion/ADS provenance into recursive analysis.

## 2026-09-03 10:50 KST

### EVTX process to LNK/Prefetch correlation

- Changed `src/forensickit/engine.py` and `tests/test_engine_pipeline.py`.
- Case-level correlation now joins normalized process-creation events to an explicitly supplied LNK only when its canonical full Windows target path matches exactly, or to Prefetch only when its bounded executable basename matches exactly. LNK path matches carry stronger confidence than Prefetch basename-only leads.
- Reciprocal observations preserve both artifact IDs/names, EventRecordID/native byte offset, parser observation/tool-run source, LNK/Prefetch observation source, process/command metadata, and Prefetch version/hash/run count. A same-case mismatching Prefetch fixture remains unlinked.
- Verified the combined multi-root EVTX + memory + LNK + matching/mismatching Prefetch E2E, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**246 passed, 0 failed**).

### Next

- Correlate EVTX process creation with exact executable paths recovered from allowlisted Registry persistence values, retaining key/value and transaction-log context.

## 2026-09-03 10:47 KST

### Cross-artifact EVTX and memory process correlation

- Changed `src/forensickit/engine.py` and `tests/test_engine_pipeline.py`.
- Case-level correlation now normalizes decimal/hex PIDs but refuses PID-only links. An EVTX process record and memory process aggregate must share the exact bounded PID plus either an exact case-insensitive Windows process basename or an exact parsed IPv4/IPv6 endpoint.
- Both artifacts receive reciprocal observations containing artifact IDs/names, matched keys, event ID/record/native byte offset, source observation IDs/tool-run sources, selected process/network rows, and cautious confidence. A mismatched same-PID event remains unlinked to guard against PID reuse and acquisition-time ambiguity.
- Verified the multi-root EVTX + memory + fake Chainsaw/Volatility E2E, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**246 passed, 0 failed**).

### Next

- Correlate normalized EVTX process creation with explicitly supplied LNK target paths and Prefetch executable records, retaining all artifact IDs and native event provenance.

## 2026-09-03 10:43 KST

### Provenance-bearing timeline exports

- Changed `src/forensickit/reporting.py`, `src/forensickit/cli.py`, `README.md`, `tests/test_workspace_extraction.py`, and `tests/test_engine_pipeline.py`.
- Every report now writes `reports/timeline.csv`; report schema v2 also embeds the same bounded timeline, and report.md renders the first 200 events with explicit truncation. Exact duplicate EventRecordIDs from Chainsaw/Hayabusa merge into one deterministic row while all source observation IDs, parser/tool-run IDs, raw stdout paths, native EVTX offsets, and activity-cluster scores remain attached.
- Timezone-aware timestamps receive an explicit UTC column. Formula-like evidence is escaped only at the CSV serialization boundary to prevent spreadsheet execution; JSON/database values remain exact.
- Verified focused report/Engine tests, `python -m compileall -q src tests scripts`, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**245 passed, 0 failed**).

### Next

- Correlate normalized EVTX process events with memory process/network records only under exact PID plus path or IP evidence, retaining both artifact/tool provenance chains.

## 2026-09-03 10:38 KST

### Bounded EVTX activity clustering and sequence scoring

- Changed `src/forensickit/profiles/windows.py`, `tests/test_rules_profiles.py`, and `tests/test_engine_pipeline.py`.
- Normalized Chainsaw/Hayabusa records are deduplicated by exact EventRecordID and sessionized only when their timestamps carry an explicit timezone. A deterministic 15-minute gap and one-hour maximum window preserve chronological evidence without inventing local timezone semantics.
- Each cluster retains UTC bounds, category counts, Event IDs/record IDs, native record offsets, selected actor/process/network/service/task fields, a capped score, and every score contribution. Explicit sequences cover failed-login→success, process→service/task persistence, PowerShell→process, execution/persistence→log clearing, and Defender change→process without declaring maliciousness.
- Focused profile and Hayabusa Engine/report tests passed. Verified `python -m compileall -q src tests scripts` and `PYTHONPATH=src python scripts/run_direct_tests.py` (**244 passed, 0 failed**).

### Next

- Export a deterministic provenance-bearing `timeline.csv` alongside the existing machine/human-readable reports.

## 2026-09-03 10:34 KST

### Hayabusa event normalization and offset correlation

- Changed `src/forensickit/tools/parsers.py`, `tests/test_tools.py`, and `tests/test_engine_pipeline.py`.
- Bounded Hayabusa CSV parsing now emits the same normalized Event ID/category, EventRecordID, timestamp, actor, process, command, IP, service, and task schema as Chainsaw JSON/JSONL. It preserves CSV row index and tool-run/generated-file provenance while retaining the raw CSV as a recursive child artifact.
- A DEEP Engine fixture proves generated Hayabusa timeline parsing, service-install categorization, exact EventRecordID-to-native-EVTX byte-offset correlation, findings, and report persistence.
- Verified `python -m compileall -q src tests scripts`, focused tool/Engine regressions, and `PYTHONPATH=src python scripts/run_direct_tests.py` (**243 passed, 0 failed**).

### Next

- Build bounded time-ordered Windows event clusters and evidence-weighted suspicious-sequence scores from the common normalized schema.

## 2026-09-03 10:30 KST

### Chainsaw EVTX record normalization and native-offset correlation

- Changed `src/forensickit/tools/parsers.py`, `src/forensickit/profiles/windows.py`, `tests/test_tools.py`, `tests/test_rules_profiles.py`, and `tests/test_engine_pipeline.py`.
- The event JSON parser now consumes bounded JSON documents and JSONL without dropping later records, flattens only bounded scalar content, recovers common nested System/EventData fields, and normalizes Event ID/category, EventRecordID, timestamp, provider/channel/computer, user, PID/process/command line, IP, service, and task evidence.
- Known login, account/group, process, service, scheduled-task, PowerShell, RDP, log-clear, and Defender Event IDs become cautious categorized leads. The Windows profile joins parser output to independently framed native records only by exact EventRecordID and retains file offset, size, chunk, timestamp sources, parser row, and tool-run provenance.
- Focused parser/profile and Engine/report E2E tests passed. Verified `python -m compileall -q src tests scripts` and `PYTHONPATH=src python scripts/run_direct_tests.py` (**242 passed, 0 failed**).

### Next

- Apply the same bounded normalized Windows-event schema to Hayabusa CSV timelines so both EVTX tool paths participate in exact native-offset correlation.

## 2026-09-03 10:22 KST

### Textual UI installed-dependency validation

- Installed Textual 8.2.8 and its Python dependencies into an isolated `/tmp` target, leaving the repository runtime dependency policy unchanged.
- Created a real triage case, launched the actual `ForensicKitTui` under Textual's headless test pilot, and verified case-summary loading, artifact/finding/run/flag table population, artifact row-selection provenance, refresh stability, and the quit binding.
- Verified `python -m compileall -q src tests scripts` and `PYTHONPATH=src python scripts/run_direct_tests.py` (**239 passed, 0 failed**).

### Next

- Add bounded EVTX record-content/Event ID normalization with exact record ID, record offset, and parser provenance.

## 2026-08-28 00:21 KST

### SMB2 NEGOTIATE exchange provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native Direct TCP reassembly now accepts bounded command-0 requests with a complete 36-byte NEGOTIATE structure, 1–64 offered dialects, valid signing bits, and bounded/aligned context declarations. Requests retain dialect names/IDs, signing mode, capabilities, raw client GUID bytes, message ID, flow, and contributing packets.
- Exact inverse responses retain NTSTATUS and response packets. Complete successful 65-byte responses additionally preserve selected dialect, signing mode, capabilities, raw server GUID, declared transact/read/write maxima, raw system/start FILETIMEs, and context count after validating security-buffer/context bounds; findings explicitly show whether the selected dialect was offered.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**92 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**239 passed, 0 failed**).

### Stop point

- Continuous development was stopped at the user's request. No additional feature was started; the only remaining queue item is the environment-dependent Textual UI validation.

## 2026-08-27 23:57 KST

### SMB3 transform-header provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native TCP/445 reassembly now inventories at most 100 complete 1 MiB Direct TCP SMB3 encryption (`FD SMB`) or compression (`FC SMB`) frames across at most 512 flows. Encryption records require the fixed 52-byte header, zero reserved field, encrypted flag, nonempty payload, and a bounded nonzero original size; compression records validate ordinary versus chained algorithm/flag/offset combinations and the same size bound.
- Findings retain type, declared original/transformed/framed sizes, flags, direction, contributing packets, and type-specific session/signature/nonce or compression algorithm/offset values. Protected bytes remain opaque: no decryptor, decompressor, key inference, or child promotion is attempted.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**91 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**238 passed, 0 failed**).

### Next

- Correlate bounded SMB2 NEGOTIATE requests/responses to retain offered/selected dialect, signing mode, capabilities, server GUID, and declared transport-size limits with exact packet provenance.

## 2026-08-27 23:52 KST

### SMB2 FileIdBothDirectoryInformation inventory

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- QUERY_DIRECTORY recovery now also accepts class 37 only after the existing successful CREATE/FileId and exact inverse status-success response correlation. Each result validates the 104-byte fixed structure, 8-byte entry chain, strict bounded long/short UTF-16LE names, and the shared 256-entry/output bounds.
- A JSONL child preserves each entry's filename/index, four raw FILETIMEs, logical/allocation sizes, attributes, EA size, short name, and 64-bit directory FileId without timezone/path inference. The finding records the exact information class, metadata schema, child ID, request/response packets, and CREATE FileId; recursive FlagHunter provenance is covered end to end.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**90 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**237 passed, 0 failed**).

### Next

- Inventory bounded SMB3 encrypted and compressed transform headers with declared sizes/flags/session identifiers and exact flow/packet provenance, without decoding protected content.

## 2026-08-27 23:46 KST

### SMB2 QUERY_DIRECTORY FileNamesInformation recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native SMB2 now accepts only command-14 requests for FileNamesInformation (class 12) whose flow/session/tree/FileId matches a successful CREATE. Exact inverse status-success responses must have complete Direct TCP/SMB2/output bounds, valid 8-byte entry chaining, no more than 256 entries, and strict bounded UTF-16LE names.
- Accepted names become one bounded newline-delimited UTF-8 child beneath the PCAP. Findings retain the child ID, share/directory path, search pattern, entry count, FileId, message ID, flow, and exact request/response packet sets; the Engine fixture proves recursive flag recovery and no spurious HTTP summary.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**89 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**236 passed, 0 failed**).

### Next

- Recover common SMB2 FileIdBothDirectoryInformation responses with bounded filename, size, timestamp, attribute, and per-entry FileId provenance.

## 2026-08-27 23:41 KST

### Native PCAP protocol-summary boundary correction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- The combined native PCAP extractor previously emitted `pcap_http_extraction` whenever any protocol produced a child, and its count included FTP/mail/SMB children even when the HTTP evidence list was empty. The gate and title count now use only the actual HTTP response-object list.
- The SMB2 WRITE Engine fixture explicitly proves protocol-specific SMB recovery no longer creates the misleading HTTP summary; real HTTP response findings retain their existing detailed evidence path.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**88 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**235 passed, 0 failed**).

### Next

- Recover bounded SMB2 QUERY_DIRECTORY FileNamesInformation responses tied to a successful directory CREATE FileId as provenance-bearing text listing children.

## 2026-08-27 23:39 KST

### SMB2 SET_INFO rename/delete-disposition provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native SMB2 now accepts bounded command-17 File information requests only for FileRenameInformation (10) and FileDispositionInformation (13). Requests must have complete structure/buffer bounds, a validated rename UTF-16LE target or exact one-byte delete flag, and a flow/session/tree/FileId matching a successful CREATE.
- Rename target, replace-if-exists/delete-pending intent, original share/path, FileId, identifiers, request packets, exact inverse NTSTATUS, and response packets are preserved in low-severity mutation findings. Captured operations remain evidence only and are never applied to the local filesystem.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**88 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**235 passed, 0 failed**).

### Next

- Correct the generic PCAP extraction summary so non-HTTP-only child recovery does not emit a misleading HTTP-object finding.

## 2026-08-27 23:35 KST

### SMB2 transfer size validation against CLOSE

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Successful CLOSE lifecycle records now retain session/tree IDs so recovered READ/WRITE streams can match the exact flow/session/tree/FileId. When such a CLOSE is present, child promotion additionally requires recovered byte length to equal final EndOfFile; an explicit mismatch fixture proves a contiguous, acknowledged WRITE is withheld when it is not the complete final file.
- Accepted children retain CLOSE request/response packet indices, EndOfFile, and an explicit size-match field. Captures without a successful CLOSE retain the prior, clearly weaker contiguous/acknowledged recovery path rather than assuming a missing lifecycle record.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**87 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**234 passed, 0 failed**).

### Next

- Parse bounded SMB2 SET_INFO FileRenameInformation and FileDispositionInformation operations only for successful CREATE FileIds, preserving requested mutation and exact response provenance without applying it to the filesystem.

## 2026-08-27 23:32 KST

### SMB2 CLOSE lifecycle provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- CLOSE requests are retained only when their exact client flow/session/tree and 128-bit FileId match a successful CREATE. An exact inverse command-6 response with the same message/session/tree identifiers supplies NTSTATUS and response packet provenance; final metadata is parsed only from a complete successful 60-byte CLOSE response.
- Findings preserve share/relative filename, FileId, message and both packet sets, allocation size, EndOfFile, file attributes, and four raw independently stored FILETIME values. Raw integers are retained rather than inventing timezone semantics.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**87 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**234 passed, 0 failed**).

### Next

- Use a successful correlated CLOSE EndOfFile as a stronger completeness gate for recovered SMB2 READ/WRITE children, retaining the size comparison in provenance.

## 2026-08-27 23:29 KST

### SMB2 TREE_CONNECT share-path correlation

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Bounded SMB2 parsing now retains complete TREE_CONNECT requests with validated UTF-16LE UNC paths, then maps them only when an exact inverse response with the same message/session identifiers succeeds and supplies a tree ID. The mapping is bounded to 512 pending tree requests and remains scoped to the exact client flow/session/tree tuple.
- Subsequent CREATE findings retain the UNC share plus both TREE_CONNECT packet sets. Recovered WRITE and READ objects inherit the validated share path alongside their relative SMB path and FileId provenance; no share is inferred from an unmatched or failed response.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**86 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**233 passed, 0 failed**).

### Next

- Correlate bounded SMB2 CLOSE request/response pairs to successful CREATE FileIds and preserve NTSTATUS, final EndOfFile, attributes, and independently stored timestamps for transfer lifecycle verification.

## 2026-08-27 23:25 KST

### Bounded SMB2 READ download recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- READ requests are retained only when their flow/session/tree and 128-bit FileId match a successful CREATE. Exact inverse status-success READ responses must validate the 17-byte structure, declared data offset/length, response bounds, and requested maximum before their bytes are accepted.
- At most 256 response chunks per file are assembled by the requested file offset. Only nonempty conflict-free data contiguous from offset zero and within the configured child limit becomes a recursively analyzed PCAP child. Findings retain the SMB path/FileId, request message/packet provenance, response data packets, and child ID.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**85 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**232 passed, 0 failed**).

### Next

- Correlate bounded SMB2 TREE_CONNECT request/response pairs so CREATE and recovered READ/WRITE artifacts retain the validated UNC share path in addition to their relative SMB path.

## 2026-08-27 23:22 KST

### Bounded SMB2 WRITE upload recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- WRITE requests are accepted only on the same client flow/session/tree and 128-bit FileId returned by a successful correlated CREATE. Each chunk must have complete declared data bounds and an exact inverse status-success WRITE response whose Count equals the request length.
- At capture end, at most 256 acknowledged chunks per file are sorted by offset. Only a nonempty stream contiguous from offset zero and within the configured child-size bound is registered beneath the PCAP; gaps, conflicting overwrites, saturation, and oversized output are withheld. Findings retain the SMB path/FileId, WRITE message IDs, request packets, response packets, and child ID; recursive FlagHunter runs normally.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**84 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**231 passed, 0 failed**).

### Next

- Recover bounded SMB2 READ response bytes only after an exact request/FileId/response correlation, applying the same contiguous-offset and child-provenance safeguards.

## 2026-08-27 23:18 KST

### SMB2 CREATE response/FileId correlation

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Bounded CREATE requests remain pending until capture completion and now correlate only with command-5 responses on the exact inverse flow whose message/session/tree identifiers all match. Every matched response retains NTSTATUS and response packet indices; persistent/volatile FileId fields are accepted only for status-success responses with the complete 89-byte CREATE response structure.
- The first focused run exposed a mechanical initialization placement error that put the new SMB record variables into the adjacent FTP iterator. The declarations were moved into their exact functions before final verification; no failed run was reported as success.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**83 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**230 passed, 0 failed**).

### Next

- Reassemble bounded SMB2 WRITE request payloads only for successfully correlated CREATE FileIds, retaining file offsets and packet/message provenance before child-artifact registration.

## 2026-08-27 23:14 KST

### Bounded SMB2 CREATE request provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Added sequence-aware reassembly for complete NetBIOS Session Service frames on TCP/445, bounded to 512 flows, 1 MiB per declared message, 16 compound commands, and 100 CREATE operations. A strict SMB2 CREATE request parser validates header/command/name offsets and decodes only a nonempty bounded UTF-16LE path.
- Each report-visible operation retains filename, message/session/tree IDs, desired access, create disposition/options, direction, and exact contributing packet indices. Captured paths remain metadata and are never opened or executed.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**83 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**230 passed, 0 failed**).

### Next

- Correlate exact inverse SMB2 CREATE responses by message/session/tree identity and preserve NTSTATUS plus persistent/volatile FileId for later READ/WRITE linkage.

## 2026-08-27 23:11 KST

### FTP AUTH TLS transition provenance and suppression

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native FTP now accepts only a complete TCP/21 `AUTH TLS` command followed by the exact inverse `234`. It records the control flow and both packet indices, suppresses later plaintext control parsing, and clears pending command plus PASV/EPSV/PORT/EPRT transfer state for that endpoint pair so subsequent data packets cannot inherit stale plaintext correlation.
- No TLS traffic is decrypted, and non-234 replies do not create a transition or encrypted-flow state.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**82 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**229 passed, 0 failed**).

### Next

- Add a bounded native SMB2 CREATE operation inventory with filename, message/session/tree identifiers, direction, and packet provenance as the first safe SMB transfer-correlation layer.

## 2026-08-27 23:08 KST

### POP3 STLS transition provenance and suppression

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native POP3 now recognizes only a complete TCP/110 `STLS` command paired with the exact inverse `+OK`. The accepted transition preserves client/server flow and command/response packet indices in a report finding; both directions are then excluded from RETR plaintext recovery. A contiguous synthetic post-transition RETR/response proves no message child is promoted.
- Rejected STLS responses do not create transition provenance or enable encrypted-flow state. No TLS bytes are decrypted or interpreted as POP3.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**81 passed, 0 failed**), and PTY-tracked `python scripts/run_direct_tests.py` (**228 passed, 0 failed**).

### Next

- Add bounded FTP AUTH TLS transition provenance and suppress subsequent plaintext FTP control/data correlation on the exact control flow.

## 2026-08-27 23:05 KST

### IMAP STARTTLS transition provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, `src/forensickit/engine.py`, and `tests/test_pcap_reassembly.py`.
- Added a separately bounded IMAP STARTTLS iterator that accepts only a complete client tagged STARTTLS command and the same tag's exact inverse server `OK`. The transition preserves tag, client/server flow, and command/response packet indices in `pcap_imap_starttls_transition`.
- The regression exposed an Engine gate that persisted extraction findings only when a child artifact existed. Findings are now persisted independently of generated children, so standalone IMAP and SMTP encryption transitions remain report-visible without manufacturing an artifact.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**80 passed, 0 failed**), and a PTY-tracked `python scripts/run_direct_tests.py` (**227 passed, 0 failed**).

### Next

- Add bounded POP3 STLS transition provenance and suppress subsequent plaintext RETR recovery on the exact flow.

## 2026-08-27 22:42 KST

### IMAP STARTTLS plaintext suppression

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- The bounded IMAP FETCH parser now tracks client tagged `STARTTLS` commands. After the exact inverse server tagged `OK`, both directions are marked encrypted and excluded from subsequent native plaintext FETCH interpretation. A contiguous synthetic post-transition FETCH/literal sequence proves no child is recovered.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**80 passed, 0 failed**). A broad two-batch runner was still active after its observation boundary and later exited without its aggregate output, so no new broad-pass count is claimed.

### Next

- Completed by the subsequent IMAP STARTTLS transition-provenance entry.

## 2026-08-27 22:42 KST

### IMAP FETCH MIME attachment extraction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- Recovered IMAP FETCH `.eml` children now use the existing bounded MIME attachment policy: up to 32 parts, declared attachment or Content-ID inline eligibility, safe decoded names, artifact limits, lineage, and per-attachment provenance. The Base64 regression proves IMAP PCAP → literal-backed message → attachment recursion and FlagHunter recovery.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**79 passed, 0 failed**). Two single broad invocations produced no completion line and left no runner process; the same complete module set then passed in non-overlapping direct-runner batches: **118 passed, 0 failed** and **108 passed, 0 failed** (**226 total, 0 failed**).

### Next

- Completed by the subsequent IMAP STARTTLS suppression entry.

## 2026-08-27 22:42 KST

### Bounded IMAP FETCH message recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native recovery now accepts a bounded full-message `BODY[]`/`RFC822` client FETCH on TCP/143 only when the inverse untagged FETCH response declares an exact literal length and the same client tag later receives `OK`. The literal is recovered byte-for-byte with packet provenance, then registered as a recursive `.eml` child. Lines, literal state, flow count, literal length, scan size, and object count are bounded.
- An initial finding-construction syntax error was corrected before verification; no partial test result was recorded as success. Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**78 passed, 0 failed**), and a clean retry of `python scripts/run_direct_tests.py` (**225 passed, 0 failed**).

### Next

- Completed by the subsequent IMAP MIME attachment extraction entry.

## 2026-08-27 22:42 KST

### POP3 RETR MIME attachment extraction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- POP3 RETR `.eml` children now receive the same bounded MIME policy as SMTP: a maximum of 32 walked parts, declared attachments and Content-ID inline objects, safe decoded names, size/count/depth enforcement, child lineage, and attachment-specific findings. The synthetic Base64 fixture verifies POP3 PCAP → recovered message → attachment registration and recursive FlagHunter provenance.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**77 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**224 passed, 0 failed**).

### Next

- Completed by the subsequent IMAP FETCH recovery entry.

## 2026-08-27 22:42 KST

### Bounded POP3 RETR message recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native PCAP recovery now accepts only `RETR <message-number>` commands on TCP/110 paired with their exact inverse `+OK` response. It reassembles the complete POP3 dot-terminated multiline body, dot-unstuffs it, records command/response/body packet provenance, and registers a recursively analyzed `.eml` child. Negative `-ERR` and exact retransmission fixtures prevent false promotion and duplicate bytes.
- The retransmission fixture exposed a shared `_TcpFlow` flaw after a consumer had advanced its window: an old overlapping segment could be prepended. Consumed-prefix overlap is now ignored, preserving bounded TCP stream semantics for all consumers.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**76 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**223 passed, 0 failed**).

### Next

- Completed by the subsequent POP3 MIME attachment extraction entry.

## 2026-08-27 22:42 KST

### SMTP BDAT MIME attachment extraction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- Complete BDAT-derived `.eml` children now use the same bounded standard-library MIME walk as DATA messages: at most 32 parts, declared attachments plus inline objects only when a Content-ID exists, safe RFC 2231/5987 filename recovery, byte/count limits, parent-child registration, and attachment findings. A synthetic Base64 fixture proves root PCAP → BDAT `.eml` → attachment lineage and recursive FlagHunter recovery.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**74 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**221 passed, 0 failed**).

### Next

- Add bounded POP3 RETR message recovery with exact command/positive-response/body provenance and child-artifact registration.

## 2026-08-27 23:24 KST

### SMTP BDAT final-response and incomplete-stream boundaries

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- A complete BDAT LAST message now waits through capture processing so an exact inverse server 250/251/252/4xx/5xx line can be preserved as final-response code and packet provenance. The extraction finding reports this state without asserting delivery semantics. A separate negative fixture proves a stream with no LAST is never promoted to a child artifact.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**73 passed, 0 failed**), and the preceding clean broad run `python scripts/run_direct_tests.py` (**219 passed, 0 failed**).

### Next

- Completed by the subsequent BDAT MIME attachment extraction entry.

## 2026-08-27 23:18 KST

### SMTP BDAT retransmission-safe continuation regression

- Changed `tests/test_pcap_reassembly.py`.
- Added a split BDAT command/payload fixture that repeats the first TCP range. The completed message bytes, payload packet indices, and command packet indices contain only the accepted continuation packets, proving the existing bounded `_TcpFlow` integration does not duplicate retransmitted data.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly`: **72 passed, 0 failed**.
- A broad test invocation overlapped with a pre-existing runner process; both processes were terminated rather than using incomplete output. The next broad regression will be run from a clean single-process state.

### Next

- Preserve SMTP BDAT final 250/251/252/4xx/5xx response provenance using the same exact inverse control-flow boundary.

## 2026-08-27 23:12 KST

### Bounded SMTP BDAT chunked-message recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native SMTP now reconstructs BDAT only from strict `BDAT <length> [LAST]` commands on the client→server TCP/25 flow. It consumes exactly the declared byte count from the sequence-aware buffer, joins chunks only after `LAST`, bounds each message, and records both chunk-command and data packet provenance before registering the `.eml` child.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**71 passed, 0 failed**), and a retried `python scripts/run_direct_tests.py` (**218 passed, 0 failed**).

### Next

- Add explicit regression coverage for split/retransmitted BDAT command and payload continuations.

## 2026-08-27 23:05 KST

### Bounded SMTP STARTTLS transition suppression

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Exact STARTTLS and inverse 220 control lines are now reassembled with packet provenance. Once paired, that bidirectional flow is excluded from native SMTP plaintext DATA recovery; the extractor records a reportable transition warning and, when extraction findings are otherwise emitted, an explicit STARTTLS transition finding. No TLS bytes are decrypted or treated as SMTP text.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**70 passed, 0 failed**), and a retried `python scripts/run_direct_tests.py` (**217 passed, 0 failed**).

### Next

- Recover bounded SMTP BDAT chunked messages with exact declared lengths and child-artifact provenance.

## 2026-08-27 22:58 KST

### Bounded SMTP final 251/252 forwarding provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Final SMTP 251/252 replies on the exact inverse control flow now become explicit forwarding fields, distinct from local 250 acceptance and 4xx/5xx rejection. This preserves the server's stated handoff/verification state without claiming end-to-end delivery.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**69 passed, 0 failed**), and a retried `python scripts/run_direct_tests.py` (**216 passed, 0 failed**).

### Next

- Record SMTP STARTTLS transition provenance and suppress further native plaintext DATA recovery on that flow.

## 2026-08-27 22:53 KST

### Bounded SMTP final 4xx/5xx rejection provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Completed messages now retain a distinct rejection code and packet index when the exact inverse SMTP control flow returns a final 4xx/5xx line. Rejection is deliberately not populated as acceptance; the recovered DATA bytes remain available as sent evidence and the finding exposes both success and rejection fields.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**68 passed, 0 failed**), and a retried `python scripts/run_direct_tests.py` (**215 passed, 0 failed**).

### Next

- Preserve exact SMTP 251/252 forwarding-acceptance statuses separately from ordinary local 250 acceptance.

## 2026-08-27 22:47 KST

### Bounded SMTP final 250 acceptance provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- A completed SMTP DATA message is held in a bounded pending list until capture completion. Only a complete `250` line on its exact inverse TCP/25 control flow attaches acceptance code and packet index; unrelated or prior 250 responses cannot create or enrich a message. The SMTP extraction finding preserves the resulting acceptance fields.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**67 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**214 passed, 0 failed**).

### Next

- Preserve exact final SMTP 4xx/5xx rejection responses with the same pending-message and flow provenance constraints.

## 2026-08-27 22:42 KST

### Bounded SMTP multipart/alternative FlagHunter provenance

- Changed `src/forensickit/engine.py` and `tests/test_pcap_reassembly.py`.
- Recovered `.eml` children that are top-level `multipart/alternative` now have up to 16 immediate text parts scanned with `smtp_multipart_alternative_flag_hunter` and MIME-part location provenance. Identical flag values across alternatives are emitted once from this MIME-specific path, avoiding candidate inflation while leaving ordinary raw-message scanning intact.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**67 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**214 passed, 0 failed**).

### Next

- Preserve bounded SMTP final `250` acceptance-response provenance for recovered DATA messages.

## 2026-08-27 22:37 KST

### Bounded SMTP inline Content-ID object extraction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- Declared MIME `inline` parts are now promoted only when they also carry Content-ID. They use the normal decoded-payload, child-size/depth, and safe-name path, while the attachment finding preserves the Content-ID and disposition so inline evidence remains traceable to its SMTP message.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**66 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**213 passed, 0 failed**).

### Next

- Give bounded SMTP multipart/alternative text parts a MIME-specific FlagHunter provenance without duplicate candidate inflation.

## 2026-08-27 22:33 KST

### Bounded SMTP RFC 2231/5987 attachment filename recovery

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- SMTP attachment registration now accepts only a nonempty, NUL-free RFC 2231/5987-decoded filename supplied by the standard-library MIME parser, capped at 255 characters; otherwise it uses a deterministic fallback. Storage remains mediated by `safe_name`, while logical filename provenance preserves the decoded value. A UTF-8 `filename*=` attachment reaches the Engine as `ctf flag.txt`.
- The first focused regression exposed an accidental class-scope break caused by helper placement (`ExtractionManager.extract_supported` missing); the helper was moved to module scope before final verification.
- Verified with `python -m compileall -q src tests scripts`, `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**65 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**212 passed, 0 failed**).

### Next

- Extract bounded SMTP inline Content-ID MIME objects as provenance-bearing child artifacts.

## 2026-08-27 22:28 KST

### Bounded SMTP nested-message attachment extraction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- A declared `message/rfc822` attachment now serializes exactly one parsed nested MIME message into a bounded `.eml` grandchild beneath its recovered SMTP message. It uses the same attachment count, artifact size, depth, hashing, and provenance rules as ordinary MIME bytes; malformed or multiple nested payloads are not guessed.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly`: **65 passed, 0 failed**.

### Next

- Recover bounded RFC 2231/5987 SMTP attachment filenames while retaining safe workspace storage.

## 2026-08-27 22:25 KST

### Bounded SMTP MIME attachment extraction

- Changed `src/forensickit/extraction.py` and `tests/test_pcap_reassembly.py`.
- Recovered `.eml` artifacts are now parsed with the Python standard-library MIME parser. Up to 32 declared `attachment` parts with decoded byte payloads pass through existing artifact count/size/depth checks and are registered as grandchildren beneath their message. Attachment findings preserve message/child IDs, logical name, content type, and declared transfer encoding; a Base64 attachment recursively yields its FlagHunter candidate.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly`: **64 passed, 0 failed**. The broad direct runner did not emit a result inside the 30-second observation window, so it remains pending rather than reported green.

### Next

- Recover bounded nested SMTP `message/rfc822` attachments without bypassing child-artifact limits or provenance.

## 2026-08-27 22:20 KST

### Bounded retransmission-safe SMTP DATA body reassembly

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- SMTP message body assembly now uses the existing sequence-aware bounded TCP flow state instead of appending capture-order bytes. It accepts only contiguous data, buffers a finite out-of-order successor, removes exact retransmissions from body/provenance, and evaluates the SMTP terminator only on the reassembled bytes.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**63 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**210 passed, 0 failed**).

### Next

- Extract bounded Base64/quoted-printable SMTP MIME attachments into recursive child artifacts with message/control provenance.

## 2026-08-27 22:15 KST

### Bounded SMTP DATA/354 control continuation reassembly

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- SMTP control directions now use a 512-flow/64 KiB retransmission-safe TCP buffer and update DATA readiness only after complete CRLF lines. The regression splits both DATA and the inverse 354 reply across packets, then verifies the message child, data/control packet provenance, and Engine finding survive unchanged.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**63 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**210 passed, 0 failed**).

### Next

- Reassemble bounded SMTP DATA body bytes with exact TCP sequence/retransmission safeguards before evaluating the dot terminator.

## 2026-08-27 22:10 KST

### Bounded SMTP DATA message recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native PCAP extraction now registers a complete SMTP DATA body only after a client `DATA` command and an exact inverse TCP/25 `354` response. The message must end with the SMTP dot terminator, is limited by the configured child size, reverses dot-stuffing, retains message/data-control packet provenance, and enters ordinary recursive analysis as an `.eml` child.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly`: **63 passed, 0 failed**. The broad direct runner again did not emit a result within the 30-second observation window; no green broad-regression claim is made for this unit.

### Next

- Add bounded retransmission-safe TCP continuation reassembly for SMTP DATA/354 control exchanges.

## 2026-08-27 22:05 KST

### Bounded FTP completion/error provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- The bounded FTP control parser now associates a complete server `226` or 4xx/5xx line only with the command packet active on that exact inverse control flow. Recovered data children preserve code and packet index as endpoint-completion evidence; no completion response alone creates a child or is joined across flows.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**62 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**209 passed, 0 failed**).

### Next

- Add bounded native SMTP DATA message recovery with TCP/packet provenance and child-artifact registration.

## 2026-08-27 22:00 KST

### Bounded active FTP MLSD/NLST listing recovery

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Active PORT/EPRT data-flow lookup now permits MLSD/NLST only in the same server-port-20→declared-client-port direction as RETR. A synthetic PORT→NLST chain recovers a deterministic listing child with command/data provenance; no active upload/listing direction is inferred.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly`: **62 passed, 0 failed**.
- The full direct runner exceeded repeated 30-second observation windows in this environment after the focused suite passed; its lingering process was terminated and this unrelated runner-completion issue remains to be rechecked before the next broad regression claim.

### Next

- Preserve bounded FTP transfer completion/error (`226`/`4xx`/`5xx`) control-response provenance and retry the complete direct regression.

## 2026-08-27 21:55 KST

### Bounded FTP PASV/EPSV MLSD/NLST listing recovery

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- The bounded FTP data correlator now recognizes complete MLSD/NLST control lines and names their downloaded data as deterministic listing child artifacts. It applies the existing exact PASV/EPSV server-endpoint and packet-provenance rules; list data is not parsed speculatively or treated as an executable payload.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**61 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**208 passed, 0 failed**).

### Next

- Extend MLSD/NLST listing recovery to active PORT/EPRT data flows with the same exact endpoint validation.

## 2026-08-27 21:52 KST

### Bounded FTP active EPRT object recovery

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Active-mode state now accepts a complete EPRT command only when its delimiter structure is complete, address family is IPv4 (`1`), its declared address exactly equals the observed control client, and its port is 1–65535. RETR/STOR then retain the prior observed server-port-20 data direction rule; other EPRT families or endpoints are not guessed.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**60 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**207 passed, 0 failed**).

### Next

- Recover bounded FTP MLSD/NLST data listings through the existing exact FTP control/data correlation path.

## 2026-08-27 21:49 KST

### Bounded FTP active PORT object recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native FTP now accepts active-mode RETR only when a complete `PORT` command declares the exact observed control-channel client IPv4 address and a nonzero port, followed by RETR and an observed server-port-20→declared-client-port data flow. STOR uses the inverse data direction. Findings now call the control-side setup packet generically rather than mislabelling PORT as a PASV response.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**59 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**206 passed, 0 failed**).

### Next

- Add bounded active-mode EPRT control/data correlation with exact observed IPv4 endpoint validation.

## 2026-08-27 21:44 KST

### Bounded FTP control-line continuation reassembly

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- FTP TCP/21 directions now use the existing retransmission-safe TCP buffer with a 512-flow / 64 KiB hard cap. A command or PASV/EPSV reply enters transfer state only after an in-order, complete CRLF line; oversized unterminated lines are discarded. The regression splits both `RETR` and `227` across packets and proves the recovered child retains the final command/reply packet references plus data packet provenance.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**58 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**205 passed, 0 failed**).

### Next

- Add bounded active-mode IPv4 `PORT` control/data correlation without accepting an unobserved endpoint.

## 2026-08-27 21:39 KST

### Bounded FTP EPSV object recovery

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- The FTP correlator now accepts a syntactically bounded `229` EPSV response and uses only its 1–65535 port together with the observed TCP/21 server endpoint and client endpoint. Both RETR and STOR retain the same exact data-direction requirement and packet provenance as PASV; malformed or zero/out-of-range ports are ignored.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**58 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**205 passed, 0 failed**).

### Next

- Add bounded TCP-continuation reassembly for FTP control commands and PASV/EPSV replies before correlating data flows.

## 2026-08-27 21:36 KST

### Bounded FTP PASV STOR object recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- The same bounded FTP correlator now accepts `STOR` only when client→server data targets the exact observed server PASV port after a matching control command and inverse TCP/21 `227` response. Extracted child findings distinguish the command direction and preserve command, PASV, and data packet provenance.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**57 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**204 passed, 0 failed**).

### Next

- Add bounded FTP EPSV control/data correlation using the control-channel server endpoint and the declared passive port.

## 2026-08-27 21:34 KST

### Bounded FTP PASV RETR object recovery

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native PCAP extraction now accepts a download only after a client `RETR`, its exact inverse TCP/21 `227` PASV response, and an observed server→client data flow using that PASV port. It ignores the advertised IP in favor of the control endpoint, uses bounded retransmission-safe TCP assembly, registers the recovered file as a child, and records RETR/PASV/data packet provenance. No active-mode, upload, or TLS FTP traffic is guessed.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_workspace_extraction` (**62 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**203 passed, 0 failed**).

### Next

- Recover bounded PASV `STOR` uploads using the same exact control/data endpoint correlation and child-artifact provenance.

## 2026-08-27 21:28 KST

### Bounded RFC 2231 continued HTTP filename recovery

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Native HTTP object naming now reconstructs at most 16 contiguous `filename*0`…`filename*N` parts. Extended continuations require a complete UTF-8 `filename*0*` declaration and strict percent-decoding; duplicate, missing, malformed, oversized, or mixed extended/plain sequences are rejected so the normal `filename=` fallback remains authoritative. The recovered logical name still enters the existing safe child-artifact storage boundary.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**55 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**202 passed, 0 failed**).

### Next

- Add bounded native FTP control/data transfer correlation and extracted-object provenance.

## 2026-08-27 21:26 KST

### RFC 5987 HTTP filename recovery

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Native HTTP and multipart object naming now prefers a bounded UTF-8 RFC 5987 `Content-Disposition: filename*=` value when it validates, falling back to the existing filename/content-type path otherwise. Child writes remain constrained by the existing workspace `safe_name` layer.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly`: **54 passed, 0 failed**.

### Next

- Add bounded RFC 2231 continued multipart filename parameter recovery while preserving the same safe child-artifact storage boundary.

## 2026-08-27 21:25 KST

### Bounded multipart quoted-printable transfer decoding

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Declared multipart `Content-Transfer-Encoding: quoted-printable` is now decoded by the standard-library parser only within the existing multipart child-size bound. The child and multipart provenance use the decoded bytes and retain the declared/decoded encoding fields; the previously implemented Base64 and identity paths are unchanged.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**53 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**200 passed, 0 failed**).

### Next

- Recover bounded RFC 5987 `Content-Disposition` `filename*` metadata for HTTP response objects and multipart parts without allowing a decoded name to escape workspace-safe storage.

## 2026-08-27 21:24 KST

### Bounded multipart Base64 transfer decoding

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Declared multipart `Content-Transfer-Encoding: base64` now accepts only strict Base64 after MIME whitespace removal and only within the configured child size limit. The decoded bytes become the child artifact; identity encodings pass through, while malformed or unsupported encodings preserve the original bytes and a reproducible extraction error. Multipart findings record declared/decoded transfer encoding and decode status.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_workspace_extraction` (**58 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**199 passed, 0 failed**).

### Next

- Add bounded quoted-printable multipart transfer decoding with the same declared-header and child-artifact provenance safeguards.

## 2026-08-27 21:23 KST

### Bounded HTTP request/response pairing provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native extraction now reassembles only complete HTTP/1.x request headers and declared request bodies, queues at most 100 requests per direction, and attaches a request to a response only for the exact inverse TCP 4-tuple. Recovered objects/parts retain request method, Host, target, and contributing request packet indices; unmatched or saturated directions deliberately remain unpaired. Extraction findings preserve both request and response provenance.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_workspace_extraction` (**57 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**198 passed, 0 failed**).

### Next

- Decode declared HTTP multipart Base64 Content-Transfer-Encoding within the existing size limit and preserve the original transfer header plus decode outcome in child-artifact findings.

## 2026-08-27 19:20 KST

### HTTP response-object packet provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Every bounded native HTTP object (including multipart parts) now retains the response endpoint/port flow and the exact contributing capture packet indices. The 8,192-range cap explicitly marks packet provenance incomplete rather than emitting a misleading partial set; retransmitted TCP bytes are excluded and back-to-back responses retain separate packet sets. Child-extraction findings preserve that provenance alongside their artifact IDs and HTTP metadata.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**50 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**197 passed, 0 failed**).

### Next

- Pair bounded native HTTP requests and responses only by exact inverse TCP flow, preserving method/Host/target and contributing request-packet provenance.

## 2026-08-27 19:17 KST

### Bounded HTTP multipart response-part extraction

- Verified the existing `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py` implementation now splits only complete, declared-boundary multipart HTTP response bodies (32-part and configured body-size caps), preserves each part's Content-Type/Content-Disposition, and registers each part as a child with a `pcap_http_multipart_extraction` finding that cites its artifact ID and metadata.
- Updated `CAPABILITY_MATRIX.md`, `KNOWN_LIMITATIONS.md`, and `WORK_QUEUE.md` to reflect the supported bounded multipart path. Textual remains unavailable on this workstation (`ModuleNotFoundError`), so its interactive validation stays environment-dependent rather than blocking implementation work.
- Verified with `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_workspace_extraction`: **55 passed, 0 failed**.

### Next

- Preserve exact bounded TCP flow and contributing packet provenance for each recovered native HTTP object/part, then retain it through child-artifact findings.

## 2026-08-27 19:05 KST

### Bounded HTTP gzip/deflate object decoding

- Changed `src/forensickit/pcap.py`, `src/forensickit/extraction.py`, and `tests/test_pcap_reassembly.py`.
- Native PCAP HTTP recovery now decodes declared `Content-Encoding: gzip` and zlib/raw `deflate` chains in reverse encoding order, bounded by the child-artifact size limit. The compatibility iterator retains its prior `(name, body)` interface. The extraction path preserves original encoding, decoded order, encoded/decoded sizes, and child artifact ID in `pcap_http_content_decoding`; unsupported/malformed/oversized encodings retain their original body and a reproducible extraction error.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_workspace_extraction` (**53 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**194 passed, 0 failed**).

### Next

- Add bounded HTTP multipart response-part extraction with per-part Content-Disposition and content-type provenance; Textual UI validation remains deferred because this workstation has no locally installed `textual` package.

## 2026-08-27 19:01 KST

### TLS Certificate bounded TCP-continuation reassembly

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, `tests/test_pcap_reassembly.py`, and `tests/test_rules_profiles.py`.
- TLS Certificate metadata now follows at most 4,096 in-order TCP flows, each capped to one 64 KiB declared record. Exact duplicate byte ranges are idempotent and do not enter packet provenance; sequence gaps, overlong continuations, malformed completed records, flow-state saturation, and capture-end incomplete records produce distinct bounded observations/findings. No TLS traffic is decrypted.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_rules_profiles` (**70 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**192 passed, 0 failed**).

### Next

- Add bounded native HTTP gzip/deflate content decoding for extracted PCAP response objects, preserving Content-Encoding and generated-object provenance; Textual UI validation remains deferred because this workstation has no locally installed `textual` package.

## 2026-08-27 19:02 KST

### TLS Certificate record inventory

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, `tests/test_pcap_reassembly.py`, and `tests/test_rules_profiles.py`.
- Native PCAP triage now validates complete, single-record TLS 1.2 and TLS 1.3 Certificate handshakes. It inventories at most 16 opaque DER-framed certificate entries, preserving record version, TLS format, certificate lengths, SHA-256 fingerprints, TLS 1.3 request-context length, and exact packet/endpoint/port provenance. Malformed complete-looking records become bounded structural observations/findings. It neither decrypts traffic nor claims subject/issuer semantics.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly tests.test_rules_profiles` (**66 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**188 passed, 0 failed**).

### Next

- Extend the bounded Certificate record inventory to exact in-order TCP continuations with explicit incomplete/gap/overflow/retransmission provenance; Textual UI validation remains deferred because this workstation has no locally installed `textual` package.

## 2026-08-27 18:52 KST

### TLS ServerHello continuation retransmission regression

- Changed `tests/test_pcap_reassembly.py`.
- The ServerHello reassembly regression now retransmits an already accepted second TCP continuation (rather than only the first record segment). It proves exact duplicate continuation bytes neither alter packet provenance nor abort the bounded state: the completed ServerHello keeps packet indices `[1, 2, 4]` and excludes retransmission packet `3`.
- Verified with `python -m compileall -q src tests scripts`, focused `python scripts/run_direct_tests.py tests.test_pcap_reassembly` (**39 passed, 0 failed**), and `python scripts/run_direct_tests.py` (**184 passed, 0 failed**).

### Next

- Validate the Textual UI if the optional dependency is now locally installed; otherwise continue with bounded TLS certificate-record metadata inventory and provenance.

## 2026-08-27 14:37 KST

### TLS ServerHello bounded TCP-continuation reassembly

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, `tests/test_pcap_reassembly.py`, and `tests/test_rules_profiles.py`.
- Native PCAP triage now tracks at most 4,096 incomplete ServerHello flows and 64 KiB per declared TLS record. Only exact TCP sequence continuations are joined; completed metadata carries all contributing packet indices. Capture-end incomplete state, sequence gaps, length overflow, and flow-state saturation remain explicit bounded observations/findings, without TLS decryption.
- Verified with `python -m compileall -q src tests scripts`, focused ServerHello continuation/profile smokes, and `python scripts/run_direct_tests.py`: **183 passed, 0 failed**.

### Next

- Add synthetic regression coverage for exact retransmitted TLS ServerHello continuation bytes, which native reassembly already treats as idempotent.

## 2026-08-27 14:37 KST

### TLS ALPN offer/selection mismatch finding

- Changed `src/forensickit/profiles/pcap.py`, `tests/test_pcap_reassembly.py`, and `tests/test_rules_profiles.py`.
- A correlated inverse-flow TLS negotiation now emits a low-severity `pcap_tls_negotiation_anomaly` only when its complete ServerHello selects a concrete ALPN absent from the complete ClientHello offer. The report evidence retains both packet references and is explicitly worded as a capture/packet-review lead, not a TLS verdict.
- Verified with `python -m compileall -q src tests scripts`, focused PCAP/profile smokes, and `python scripts/run_direct_tests.py`: **180 passed, 0 failed**.

### Next

- Add bounded exact-sequence TLS ServerHello continuation reassembly and preserve incomplete/gap/overflow provenance without decrypting traffic.

## 2026-08-27 14:37 KST

### TLS ClientHello/ServerHello inverse-flow ALPN correlation

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Complete ClientHello offers and later ServerHello selections now correlate only when source/destination addresses and ports are exact inverses. The bounded negotiation inventory retains both sides' packet provenance, SNI, offered/selected ALPN, compatibility state, and selected cipher suite. It performs no TLS decryption and never guesses across unmatched flows.
- Verified with `python -m compileall -q src tests scripts`, focused inverse-flow negotiation smoke, and `python scripts/run_direct_tests.py`: **178 passed, 0 failed**.

### Next

- Promote an inverse-flow negotiation whose ServerHello selected ALPN was absent from the correlated ClientHello offer to a cautious, report-visible verification finding.

## 2026-08-27 14:37 KST

### TLS ServerHello incomplete-record length provenance

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- ServerHello parser failures now retain `captured_length`, declared `expected_length`, and `incomplete` state. This distinguishes a truncated/split record from a complete malformed record while deliberately leaving ServerHello continuation reassembly disabled.
- Verified with `python -m compileall -q src tests scripts`, focused complete/incomplete ServerHello error smokes, and `python scripts/run_direct_tests.py`: **177 passed, 0 failed**.

### Next

- Correlate complete ClientHello offers and inverse-direction ServerHello selections by endpoint/port flow, preserving both packet indices and compatibility state without decrypting TLS.

## 2026-08-27 14:34 KST

### TLS ServerHello structural-error provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- Complete TLS-looking ServerHello packets that fail bounded record/extension checks now retain exact packet/endpoint/port context in `pcap.tls.server_hello_errors`; the PCAP profile exposes a low-severity structural finding. No malformed server extension is partially decoded.
- Verified with `python -m compileall -q src tests scripts`, focused ServerHello error smoke, and `python scripts/run_direct_tests.py`: **176 passed, 0 failed**.

### Next

- Preserve declared-size/payload-size provenance for incomplete single-record ServerHello captures while leaving split reassembly disabled until bounded continuation support is added.

## 2026-08-27 14:31 KST

### TLS ServerHello selected-ALPN provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, `tests/test_pcap_reassembly.py`, and `tests/test_rules_profiles.py`.
- Native PCAP triage now parses complete plaintext ServerHello records to preserve TLS record version, selected cipher suite, selected ALPN (when present), and packet/endpoint/port provenance. It does not decrypt application data or reassemble ServerHello continuations.
- Verified with `python -m compileall -q src tests scripts`, focused ServerHello parser/profile smokes, and `python scripts/run_direct_tests.py`: **175 passed, 0 failed**.

### Next

- Record malformed complete TLS ServerHello packet provenance so native metadata parser failures remain visible rather than silently omitted.

## 2026-08-27 14:25 KST

### TLS ClientHello continuation length-detail provenance

- Changed `tests/test_pcap_reassembly.py`; the preceding source change in `src/forensickit/pcap.py` is now explicitly regression-covered.
- An overlong in-order continuation now proves native triage drops the record and retains packet indices plus `captured_length` and `expected_length`, instead of accepting bytes beyond the TLS record boundary.
- Verified with `python -m compileall -q src tests scripts`, focused overlong-continuation smoke, and `python scripts/run_direct_tests.py`: **173 passed, 0 failed**.

### Next

- Recover bounded plaintext ServerHello selected-ALPN metadata with packet/endpoint provenance, without decrypting TLS application traffic.

## 2026-08-27 14:23 KST

### TLS ClientHello retransmission-safe continuation

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Pending TLS ClientHello state now retains start sequence and validates an exact retransmitted byte range against already buffered bytes. Exact retransmissions leave original packet provenance unchanged; partial overlaps or modified/out-of-order data remain structural errors rather than being merged.
- Verified with `python -m compileall -q src tests`, focused retransmission smoke, and `python scripts/run_direct_tests.py`: **172 passed, 0 failed**.

### Next

- Preserve expected/captured record-length detail for ClientHello continuation errors so truncation and overflow evidence is directly report-filterable.

## 2026-08-27 14:22 KST

### TLS ClientHello continuation gap provenance

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Pending ClientHello state now records a bounded error with current/previous packet provenance when continuation sequence is not exact or a continuation exceeds the declared TLS record length. The partial handshake is discarded rather than reordered or guessed.
- Verified with `python -m compileall -q src tests`, focused continuation-gap smoke, and `python scripts/run_direct_tests.py`: **171 passed, 0 failed**.

### Next

- Treat exact duplicate continuation packets as retransmissions so they do not prematurely discard otherwise valid bounded ClientHello state or duplicate metadata.

## 2026-08-27 14:20 KST

### TLS ClientHello flow-state limit finding

- Changed `src/forensickit/profiles/pcap.py` and `tests/test_rules_profiles.py`.
- The explicit 4,096-flow ClientHello continuation cap is now a `pcap_analysis_limit` finding, making suppressed incomplete-flow state visible in reports rather than silently indistinguishable from absent TLS metadata.
- Verified with `python -m compileall -q src tests`, focused profile smoke, and `python scripts/run_direct_tests.py`: **170 passed, 0 failed**.

### Next

- Preserve gap/out-of-order/overlong continuation abandonment reason with packet provenance while continuing to avoid speculative reassembly.

## 2026-08-27 14:18 KST

### TLS ClientHello incomplete-flow provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- At capture end, native PCAP observations now expose incomplete bounded ClientHello flow state with endpoint/port, contributing packet indices, captured bytes, and the record's declared expected length. The PCAP profile reports it as an informational analysis-limit/capture-completeness finding.
- Verified with `python -m compileall -q src tests scripts`, focused incomplete-flow smoke, and `python scripts/run_direct_tests.py`: **169 passed, 0 failed**.

### Next

- Surface 4,096-flow TLS ClientHello state saturation as a report-visible analysis-limit finding.

## 2026-08-27 14:16 KST

### Bounded in-order TLS ClientHello continuation reassembly

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- PCAP triage now keeps at most 4,096 in-order TLS ClientHello flows, each bounded to 64 KiB. It joins only exact next-sequence TCP payloads until one TLS record's declared length is satisfied, then recovers SNI/ALPN with all contributing packet indices. Gaps, retransmission/out-of-order data, overlong records, and non-ClientHello traffic are not guessed or reassembled.
- Updated malformed-handshake coverage to distinguish a complete invalid record from a legitimately incomplete first segment.
- Verified with `python -m compileall -q src tests scripts`, focused TLS continuation smokes, and `python scripts/run_direct_tests.py`: **168 passed, 0 failed**.

### Next

- Surface incomplete bounded ClientHello flow state left at end of capture as a report-visible analysis-limit/provenance observation.

## 2026-08-27 14:13 KST

### TLS ClientHello structural-error provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- TLS-looking ClientHello packets that fail bounded single-record parsing now retain a compact packet/endpoint/port error record and produce a low-severity PCAP structural finding. They are not decoded speculatively or treated as ordinary printable TCP payloads.
- Verified with `python -m compileall -q src tests scripts`, focused malformed-ClientHello smoke, and `python scripts/run_direct_tests.py`: **167 passed, 0 failed**.

### Next

- Add bounded TCP-continuation handling for plaintext ClientHello metadata so ordinary split handshakes retain SNI/ALPN provenance without general TLS decryption.

## 2026-08-27 14:11 KST

### EXIF report regression and TLS ClientHello provenance

- Changed `tests/test_rules_profiles.py` and `tests/test_engine_pipeline.py` to cover valid/malformed EXIF profile findings and `report.json` persistence.
- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`. Native PCAP triage now preserves up to 500 complete plaintext ClientHello records with TLS record version, SNI, ALPN values, packet index, endpoint, and port provenance, while retaining the prior SNI summary for compatibility.
- Verified with `python -m compileall -q src tests scripts`, focused EXIF/TLS smokes, and `python scripts/run_direct_tests.py`: **166 passed, 0 failed**.

### Next

- Record bounded TLS ClientHello extension parsing errors (rather than silently discarding malformed/truncated handshakes) and expose them through a cautious PCAP integrity finding.

## 2026-08-27 14:06 KST

### JPEG EXIF profile integration

- Changed `src/forensickit/profiles/image.py`.
- Image-profile reports now preserve valid bounded EXIF IFD0 scalar metadata as an informational lead and APP1 TIFF/IFD validation errors as an integrity anomaly.
- Verified with `python -m compileall -q src tests` and `python scripts/run_direct_tests.py`: **162 passed, 0 failed**.

### Next

- Add focused Image-profile and Engine/report regressions for EXIF metadata and malformed APP1 provenance.

## 2026-08-27 14:05 KST

### JPEG EXIF APP1 TIFF scalar metadata

- Changed `src/forensickit/triage.py` and `tests/test_triage.py`.
- JPEG APP1 EXIF parsing now validates byte order, TIFF magic, IFD offset/count, and inline/referenced value bounds before recovering only bounded IFD0 Make, Model, Orientation, Software, and DateTime scalar/ASCII values. At most 32 EXIF APP1 entries are preserved; no thumbnail, sub-IFD, or image data is decoded.
- Verified with `python -m compileall -q src tests` and `python scripts/run_direct_tests.py`: **162 passed, 0 failed**.

### Next

- Promote valid EXIF scalar metadata and APP1 structural errors into explicit Image-profile report findings.

## 2026-08-27 14:03 KST

### JPEG ICC_PROFILE APP2 sequence validation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/image.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- JPEG APP2 ICC_PROFILE inventory now retains at most 100 chunk offsets, sequence numbers, declared total count, and payload lengths. It detects invalid sequence ranges, duplicate numbers, count disagreements, and incomplete sequences without reconstructing profile bytes. The Image profile reports invalid sequences as an integrity anomaly.
- Verified with `python -m compileall -q src tests scripts`, focused ICC triage/profile smokes, and `python scripts/run_direct_tests.py`: **161 passed, 0 failed**.

### Next

- Parse bounded scalar EXIF TIFF metadata directly from JPEG APP1 payloads with strict internal offsets and no image rendering.

## 2026-08-27 14:00 KST

### JPEG APP metadata and XMP flag provenance

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/image.py`, `src/forensickit/engine.py`, `tests/test_triage.py`, `tests/test_rules_profiles.py`, and `tests/test_engine_pipeline.py`.
- JPEG triage now inventories up to 100 APP segments with marker, exact file offset, declared payload length, bounded identifier bytes, and EXIF/XMP/ICC/Photoshop/JFIF classification. XMP packets are capped at 32×64 KiB and enter FlagHunter as `jpeg_xmp_flag_hunter` with APP1 source provenance; the generic raw candidate remains separately reproducible.
- Verified with `python -m compileall -q src tests scripts`, focused JPEG triage/profile/Engine smokes, and `python scripts/run_direct_tests.py`: **160 passed, 0 failed**.

### Next

- Validate bounded ICC_PROFILE APP2 chunk sequencing/completeness and surface only structural metadata anomalies.

## 2026-08-27 13:56 KST

### Bounded NTFS `$ATTRIBUTE_LIST` sampled-reference correlation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Sampled records now retain resident ATTRIBUTE_LIST extent references. A bounded correlator checks only target records already in the 32-record sample and records target-sampled/sequence-match state; unresolved targets remain unresolved. A sequence mismatch becomes a low-confidence verification lead, not an extension-record parse.
- Verified with `python -m compileall -q src tests scripts`, focused ATTRIBUTE_LIST link smokes, and `python scripts/run_direct_tests.py`: **157 passed, 0 failed**.

### Next

- Derive filterable record-zero ATTRIBUTE_LIST sequence/reference anomalies without resolving target records or nonresident attribute lists.

## 2026-08-27 13:54 KST

### Resident NTFS `$ATTRIBUTE_LIST` extent inventory

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Native triage now parses at most 64 resident ATTRIBUTE_LIST entries, retaining type, lowest VCN, record/sequence reference, instance, and optional name with strict entry/name bounds. The Disk profile reports the references as an informational inventory; it does not resolve extension records or recover their data.
- Verified with `python -m compileall -q src tests scripts`, focused ATTRIBUTE_LIST triage/profile smokes, and `python scripts/run_direct_tests.py`: **156 passed, 0 failed**.

### Next

- Correlate resident ATTRIBUTE_LIST references only to already sampled MFT records and explicitly preserve unresolved/sequence-mismatched states.

## 2026-08-27 13:53 KST

### NTFS STANDARD_INFORMATION fixed metadata

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Bounded resident STANDARD_INFORMATION parsing now retains fixed file-attribute flags/names, version/class IDs, and (where the 72-byte layout is present) owner ID, security ID, quota charge, and USN. Sampled records retain this metadata; special attributes are low-confidence review context rather than a concealment conclusion.
- No security descriptor, ACL, reparse target, compressed data, or encrypted content is read.
- Verified with `python -m compileall -q src tests scripts`, focused STANDARD_INFORMATION triage/profile smokes, and `python scripts/run_direct_tests.py`: **155 passed, 0 failed**.

### Next

- Add a bounded resident `$ATTRIBUTE_LIST` extent-reference inventory so split MFT attributes are visible without resolving extension records or data runs.

## 2026-08-27 13:51 KST

### Filterable NTFS sampled-record structural anomalies

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, and `tests/test_triage.py`, `tests/test_rules_profiles.py`.
- Native triage now derives a bounded `filesystem.ntfs.mft_sample_record_anomalies` inventory for sampled FILE signature, fixed-header bounds, and USA validation failures, retaining the record number, failed checks, fixup error, and mapped source segments. The Disk profile exposes it as a separate structural finding.
- Verified with `python -m compileall -q src tests scripts`, focused anomaly smokes, and `python scripts/run_direct_tests.py`: **154 passed, 0 failed**.

### Next

- Extend bounded STANDARD_INFORMATION resident parsing with file attributes and NTFS security identifiers for sampled-record metadata review.

## 2026-08-27 13:50 KST

### NTFS MFT sample-error profile provenance

- Changed `src/forensickit/profiles/disk.py` and `tests/test_rules_profiles.py`.
- Mapping, read, FILE-header, or USA-boundary errors that stop bounded MFT sampling now produce a report-visible structural finding while retaining the exact per-record error observation. Successful records already sampled remain available.
- Verified with `python -m compileall -q src tests`, focused profile smoke, and `python scripts/run_direct_tests.py`: **153 passed, 0 failed**.

### Next

- Normalize invalid FILE/USA/bounds states from individual sampled records into a bounded, filterable observation and profile finding.

## 2026-08-27 13:49 KST

### NTFS nonresident `$I30` INDEX_ALLOCATION metadata

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Nonresident INDEX_ALLOCATION attributes now use the same bounded data-run validator as DATA attributes and retain only VCN/size/run metadata. The Disk profile records their presence as an informational lead and explicitly states that index buffers are not read or traversed.
- Verified with `python -m compileall -q src tests scripts`, focused INDEX_ALLOCATION smokes, and `python scripts/run_direct_tests.py`: **153 passed, 0 failed**.

### Next

- Promote MFT sample mapping/USA errors into explicit structural findings while keeping individual raw error provenance.

## 2026-08-27 13:47 KST

### Bounded NTFS `$I30` reference correlation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Resident `$I30` entries now correlate only to child records already present in the bounded MFT sample. Output distinguishes matched, unresolved, sequence-mismatched, and filename-mismatched references without traversing directories or inferring a path.
- The Disk profile exposes sampled sequence/name conflicts as a cautious verification lead only.
- Verified with `python -m compileall -q src tests scripts`, focused `$I30` linking smokes, and `python scripts/run_direct_tests.py`: **152 passed, 0 failed**.

### Next

- Add bounded nonresident `$I30` INDEX_ALLOCATION run metadata inventory (sizes/run descriptors only; no index-buffer reads).

## 2026-08-27 13:46 KST

### Bounded NTFS FILE_NAME parent-reference correlation

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Sampled FILE_NAME metadata now retains parent record/sequence references. A bounded correlator links them only when the parent is also inside the MFT sample, reports unresolved parents explicitly, and marks sampled sequence mismatches as cautious stale/reuse verification leads without constructing a full path.
- Verified with `python -m compileall -q src tests`, focused parent-link triage/profile smokes, and `python scripts/run_direct_tests.py`: **151 passed, 0 failed**.

### Next

- Correlate resident `$I30` child references to the bounded MFT sample, retaining matched/unresolved/sequence-mismatch state without path inference.

## 2026-08-27 13:44 KST

### NTFS MFT non-contiguous mapped-segment provenance

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- MFT sampling now records every segment as `{logical_offset, physical_offset, length}` rather than an ambiguous offset list. The bounded mapper correctly joins a logical record range across validated non-contiguous runs while rejecting sparse, unmapped, out-of-image, and short-read ranges.
- Verified with `python -m compileall -q src tests scripts`, focused mapped-segment provenance smokes, and `python scripts/run_direct_tests.py`: **150 passed, 0 failed**.

### Next

- Correlate FILE_NAME parent references only among the bounded sampled records, preserving unresolved references rather than inferring full paths.

## 2026-08-27 13:42 KST

### Resident NTFS `$I30` directory index inventory

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Resident INDEX_ROOT parsing now validates header and entry-relative bounds, stops at its terminal entry, inventories at most 64 `$I30` FILE_NAME keys, and retains referenced MFT record/sequence numbers plus resident offsets. Sampled record summaries carry at most 128 entries into a report-visible Disk-profile inventory finding.
- INDEX_ALLOCATION buffers, path inference, and referenced file content remain untouched.
- Verified with `python -m compileall -q src tests scripts`, focused INDEX_ROOT triage/profile smokes, and `python scripts/run_direct_tests.py`: **149 passed, 0 failed**.

### Next

- Verify MFT record sampling across non-contiguous validated `$DATA` runs so report provenance identifies every physical segment used for a logical record.

## 2026-08-27 13:38 KST

### Data-run-addressed NTFS deleted-record sampling

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- After validating MFT record zero, native triage maps only its unnamed `$DATA` run list and samples at most 32 MFT records (records 1–31). It validates each FILE/USA header, records physical source offsets, in-use/deleted state, and resident FILE_NAME metadata. It does not resolve arbitrary file data, extract content, or attempt deleted-file recovery.
- The Disk profile emits a cautious `ntfs_deleted_record_lead` only for valid, not-in-use FILE records.
- Verified with `python -m compileall -q src tests scripts`, focused deleted-record triage/profile smokes, and `python scripts/run_direct_tests.py`: **148 passed, 0 failed**.

### Next

- Add a bounded `$I30` INDEX_ROOT directory-entry inventory from those already sampled records, preserving entry offsets and names without traversing index allocation buffers.

## 2026-08-27 13:34 KST

### NTFS independently stored timestamp comparison

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, and `tests/test_rules_profiles.py`.
- Bounded resident-value parsing now decodes the four FILETIME fields in STANDARD_INFORMATION and FILE_NAME attributes, plus FILE_NAME parent reference/name metadata. It emits at most 16 independently stored timestamp mismatches, only where both timestamps decode, and the Disk profile reports them as low-confidence verification leads rather than declaring timestomping.
- Verified with `python -m compileall -q src tests scripts`, focused timestamp triage/profile smokes, and `python scripts/run_direct_tests.py`: **147 passed, 0 failed**.

### Next

- Sample a bounded set of directly addressed NTFS MFT records, preserving record state and validated filename metadata to surface deleted-record leads without resolving or reading data runs.

## 2026-08-27 13:32 KST

### NTFS MFT0 USA fixup and bounded attribute/data-run provenance

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/disk.py`, `tests/test_triage.py`, `tests/test_rules_profiles.py`, and `tests/test_engine_pipeline.py`.
- Native NTFS triage now validates and applies the update-sequence array only to an in-memory record copy, inventories up to 64 attributes and 64 nonresident DATA runs, retains sparse/relative LCN metadata, and records malformed or unterminated run-list errors without reading filesystem clusters or extracting stream bytes.
- The Disk profile now exposes validated named DATA/alternate-data-stream metadata and USA/attribute structural anomalies as provenance-preserving findings. The Engine/report fixture proves no child artifact is created merely from a data-run inventory.
- Verified with `python -m compileall -q src tests scripts`, focused NTFS triage/profile/Engine smokes, and `python scripts/run_direct_tests.py`: **146 passed, 0 failed**.

### Next

- Extend bounded MFT attribute parsing with STANDARD_INFORMATION and FILE_NAME timestamp metadata, then compare independently stored timestamps for cautious timestomping leads.

## 2026-08-27 16:35 KST

### HTTP flow-state regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 142 fixture-aware synthetic tests passed after native HTTP flow-state bounds were added.

### Next

- Inspect bounded NTFS MFT parsing for the highest-value missing attribute or data-run provenance feature.

## 2026-08-27 16:31 KST

### Bounded PCAP HTTP flow-state tracking

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- Native triage now caps remembered HTTP flows at 4,096 and emits a truncation observation plus an informational analysis-limit finding. This preserves deterministic memory behavior without making the external tshark deep path unavailable.
- Verified with `python -m compileall -q src tests` and `Bounded HTTP flow-state smoke passed`.

### Next

- Run the full fixture-aware direct regression after flow-state bounding.

## 2026-08-27 16:23 KST

### TCP flow-state regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 141 fixture-aware direct synthetic tests passed after out-of-order HTTP flow suppression.

### Next

- Bound native HTTP flow-state tracking and expose explicit truncation evidence for very large captures.

## 2026-08-27 16:18 KST

### Out-of-order HTTP payload boundary

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Printable TCP candidates retain an internal flow marker only until observation emission. If a later out-of-order segment identifies the flow as HTTP, earlier temporary candidates for that exact direction are removed. Public observations never expose the internal marker.
- Verified with `python -m compileall -q src tests` and `TCP HTTP ordering boundary smokes passed`.

### Next

- Run full fixture-aware direct regression after TCP flow-state changes.

## 2026-08-27 16:08 KST

### HTTP continuation boundary for TCP payload inventory

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- The packet triage layer now remembers only flows whose observed first payload is HTTP, then suppresses their same-direction continuation segments from the non-HTTP printable inventory. This avoids losing arbitrary TCP CTF data merely because it uses an HTTP-associated port.
- Verified with `python -m compileall -q src tests` and `HTTP continuation boundary and TCP payload smoke passed`.

### Next

- Add an out-of-order HTTP segment regression so a continuation seen before the HTTP header is not incorrectly retained as a non-HTTP payload lead.

## 2026-08-27 16:00 KST

### PCAP payload candidate report provenance

- Changed `tests/test_pcap_reassembly.py`.
- Extended the TCP packet-payload Engine fixture to prove `report.json` retains the `pcap_payload_flag_hunter` source and packet location alongside the candidate value.
- Verified with `python -m compileall -q src tests` and `PCAP payload flag report provenance smoke passed`.

### Next

- Ensure HTTP continuation segments are not misclassified as standalone non-HTTP TCP printable payloads.

## 2026-08-27 15:54 KST

### PCAP payload candidate deduplication

- Changed `src/forensickit/engine.py` and `tests/test_pcap_reassembly.py`.
- The packet-payload FlagHunter now suppresses only duplicate observations with the same protocol, packet index, and text. Different packet locations continue to yield independent evidence candidates.
- Verified with `python -m compileall -q src tests` and `PCAP payload candidate dedupe smoke passed`.

### Next

- Add a report-level regression for PCAP packet-payload flag source, transform, and location provenance.

## 2026-08-27 15:47 KST

### Packet-payload FlagHunter regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 138 direct synthetic tests passed after PCAP packet-payload flag candidate integration.

### Next

- Deduplicate exact repeated printable PCAP payload candidates while retaining distinct packet locations as separate evidence.

## 2026-08-27 15:42 KST

### PCAP packet-payload FlagHunter provenance

- Changed `src/forensickit/engine.py` and `tests/test_pcap_reassembly.py`.
- Printable UDP, ICMP, and non-HTTP TCP payload observations now enter the standard bounded FlagHunter. Candidates use `pcap_payload_flag_hunter`, retain the raw transform, and record protocol, packet index, and endpoint direction in their location.
- Verified with `python -m compileall -q src tests` and `PCAP payload FlagHunter provenance smoke passed`.

### Next

- Run the complete direct synthetic suite after PCAP packet-payload FlagHunter integration.

## 2026-08-27 15:36 KST

### Cross-protocol PCAP payload summary

- Changed `src/forensickit/profiles/pcap.py` and `tests/test_pcap_reassembly.py`.
- CTF/secret-like printable UDP, ICMP, and non-HTTP TCP rows are now also exposed through one bounded `pcap.printable_payload_leads` observation while preserving the original protocol-specific observations and findings. The report includes the summary and packet/endpoint provenance.
- Verified with `python -m compileall -q src tests` and `Cross-protocol PCAP payload report smoke passed`.

### Next

- Send normalized packet payload leads through FlagHunter so raw packet flags become first-class candidates with packet provenance.

## 2026-08-27 15:29 KST

### TCP payload regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 138 fixture-aware synthetic tests passed after TCP payload inventory integration.

### Next

- Normalize investigation-relevant printable payloads across UDP, ICMP, and non-HTTP TCP into one bounded PCAP provenance summary.

## 2026-08-27 15:24 KST

### Printable non-HTTP TCP payload provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- TCP triage now captures at most 500 printable non-HTTP/non-TLS previews with packet index, endpoints, ports, and length. CTF/secret-like content produces a cautious application-context lead while HTTP remains routed through its existing bounded reassembler.
- Verified with `python -m compileall -q src tests` and `Printable TCP payload Engine smoke passed`.

### Next

- Run the complete direct regression after the TCP decoder signature and inventory additions.

## 2026-08-27 15:16 KST

### UDP/ICMP payload regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 137 fixture-aware synthetic tests passed after adding bounded UDP and ICMP payload inventories.

### Next

- Add a bounded non-HTTP TCP printable payload inventory so simple TCP CTF transfers retain packet/endpoint provenance outside HTTP reassembly.

## 2026-08-27 15:12 KST

### Printable ICMP payload provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- ICMP and ICMPv6 now expose bounded printable payload previews with packet index, endpoints, ICMP type/code, and payload length. Only CTF/secret-like content yields a cautious finding; no payload is executed or broadly decoded.
- Verified with `python -m compileall -q src tests` and `Printable ICMP payload Engine smoke passed`.

### Next

- Run the full direct suite after cumulative UDP/ICMP inventory changes.

## 2026-08-27 15:04 KST

### Printable UDP payload provenance

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- Non-DNS UDP packets now yield at most 500 printable, 2,000-byte previews with packet index, endpoints, ports, and original payload length. Only CTF/secret-like text receives a cautious PCAP finding; arbitrary binary UDP is not decoded or retained.
- Verified with `python -m compileall -q src tests` and `Printable UDP payload Engine smoke passed`.

### Next

- Add the same bounded printable inventory for ICMP/ICMPv6 payloads.

## 2026-08-27 14:57 KST

### DNS TXT reassembly request provenance

- Changed `src/forensickit/pcap.py` and `src/forensickit/profiles/pcap.py`.
- Reassembled TXT results with matched DNS requests now emit a compact `pcap.dns.txt_reassembly_request_packets` observation mapping response-fragment packet indices to request packet indices. The PCAP profile retains a derived count for report filtering.
- Verified with `python -m compileall -q src tests` and `DNS TXT reassembly request provenance smoke passed`.

### Next

- Add a bounded UDP payload inventory for non-DNS UDP CTF artifacts, retaining endpoint and packet provenance without treating payload as executable content.

## 2026-08-27 14:52 KST

### DNS retransmission regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 135 fixture-aware synthetic tests passed after adding TXT/query-label retransmission handling.

### Next

- Make request packet provenance explicit in DNS TXT reassembly profile/report evidence.

## 2026-08-27 14:48 KST

### DNS retransmission-safe fragment reconstruction

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Both DNS query-label and TXT reconstruction now drop only adjacent duplicate fragments within the already constrained flow/transaction group. This preserves deliberate non-adjacent repeats while preventing ordinary retransmissions from corrupting Base64/hex payloads; packet provenance lists retained fragment packets only.
- Verified with `python -m compileall -q src tests` and `DNS TXT/label retransmission dedupe smokes passed`.

### Next

- Run the full fixture-aware direct regression, then continue with the next PCAP extraction/correlation gap.

## 2026-08-27 14:40 KST

### Windows provenance regression sweep

- Ran `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`.
- All 133 fixture-aware direct synthetic tests passed. The test runner remains the documented offline fallback while pytest is unavailable on this workstation.

### Next

- Deduplicate repeated DNS query label fragments so retransmissions do not fabricate reconstructed payloads.

## 2026-08-27 14:35 KST

### Recycle Bin negative pairing boundary

- Changed `tests/test_engine_pipeline.py`.
- Added an invalid `$I` plus matching-name `$R` bundle fixture. The correlator emits neither companion observations nor a pair finding, proving it requires validated deletion metadata in addition to the exact suffix.
- Verified with `python -m compileall -q src tests` and `Invalid Recycle Bin non-correlation smoke passed`.

### Next

- Run the full direct synthetic suite after the cumulative EVTX/Prefetch/Recycle Bin changes.

## 2026-08-27 14:31 KST

### Recycle Bin `$I`/`$R` supplied-root correlation

- Changed `src/forensickit/engine.py` and `tests/test_engine_pipeline.py`.
- Case-level correlation now links a valid `$I` metadata root only to an explicitly supplied `$R` root with the exact suffix. Both artifacts retain a provenance observation, and the `$I` finding cites both artifact IDs. No sibling path is inferred, opened, or made a child.
- Verified with `python -m compileall -q src tests` and `Recycle Bin exact-pair Engine/report smoke passed`.

### Next

- Add a negative regression proving an invalid `$I` cannot be paired merely by a matching `$R` filename.

## 2026-08-27 14:22 KST

### Prefetch mismatch Engine/report regression

- Changed `tests/test_engine_pipeline.py`.
- Added a version-30 Prefetch E2E with a deliberately inconsistent declared size. The Engine preserves the false size-match observation and both execution-record and structural-anomaly findings through `report.json`.
- Verified with `python -m compileall -q src tests` and `Prefetch mismatch Engine/report smoke passed`.

### Next

- Inspect native Recycle Bin `$I` parser coverage for the next bounded Windows provenance improvement.

## 2026-08-27 14:14 KST

### Prefetch header integrity metadata

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, and `tests/test_triage.py`.
- Native Prefetch triage now preserves declared file size, actual-size match state, and the header executable hash in addition to version/name/run count. A declared-size mismatch becomes a cautious truncation/corruption finding rather than silently treating header fields as complete.
- Verified with `python -m compileall -q src tests` and `Prefetch header metadata smoke passed`.

### Next

- Add an Engine/profile regression for a Prefetch declared-size mismatch.

## 2026-08-27 14:06 KST

### EVTX record continuity anomaly

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, and `tests/test_triage.py`.
- Valid bounded EVTX record headers now yield at most 100 record-ID discontinuities with exact file offsets. The Windows profile reports them as a low-confidence structural lead only; cleared, exported, partial, and damaged logs remain plausible alternatives.
- Verified with `python -m compileall -q src tests` and `EVTX record continuity anomaly smoke passed`.

### Next

- Inspect Prefetch native coverage and implement the next safe version-aware metadata lead.

## 2026-08-27 13:58 KST

### EVTX record persistence and malformed framing

- Changed `tests/test_engine_pipeline.py` and `tests/test_triage.py`.
- Added an Engine/report E2E proving native EVTX record headers and the `evtx_record_inventory` finding survive into `report.json`. Added a malformed size-mirror fixture confirming that invalid records are excluded and retained only as a bounded framing error.
- Verified with `python -m compileall -q src tests`, `EVTX record Engine/report smoke passed`, and `EVTX malformed record isolation smoke passed`.

### Next

- Detect record-ID discontinuities inside bounded valid EVTX chunks as a cautious structural anomaly.

## 2026-08-27 13:49 KST

### Bounded EVTX record framing

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, and `tests/test_triage.py`.
- Native EVTX triage now validates bounded records inside valid chunks using the `**\0\0` signature, declared-size mirror, and chunk bounds. It preserves record ID, FILETIME timestamp, exact file offset, and size while deliberately leaving BinXML decoding to trusted external parsers. Windows profile surfaces the resulting inventory as an informational finding.
- Verified with `python -m compileall -q src tests` and `EVTX record inventory triage smoke passed`.

### Next

- Add a full Engine/report regression for bounded EVTX record headers, then add malformed record-size isolation.

## 2026-08-27 13:41 KST

### DNS provenance regression sweep

- Ran `python -m compileall -q src tests scripts` and the reusable `python scripts/run_direct_tests.py` fallback.
- All 126 direct synthetic tests passed with no failures. pytest remains unavailable in this workstation, so the fixture-aware runner remains the deterministic offline verification path.

### Next

- Inspect bounded native EVTX parsing and implement the next high-value Event ID/record normalization gap.

## 2026-08-27 13:37 KST

### DNS TXT reassembly request provenance

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- Reassembled DNS TXT records now retain bounded `request_packet_indices` whenever their source fragments were correlated to DNS requests. Existing uncorrelated observations remain structurally unchanged.
- Verified with `python -m compileall -q src tests` and `DNS TXT reassembly request provenance smoke passed`.

### Next

- Run the full fixture-aware direct regression after the accumulated DNS provenance changes.

## 2026-08-27 13:33 KST

### DNS transaction Engine/report regression

- Changed `tests/test_pcap_reassembly.py`.
- Extended the exact DNS request/response fixture through the full Engine and generated report. The persisted observation, `pcap_dns_transaction_inventory` finding, and packet-index evidence are present in `report.json`.
- Verified with `python -m compileall -q src tests` and `DNS transaction Engine/report smoke passed`.

### Next

- Carry request packet indices into DNS TXT reassembly evidence and its report-level finding.

## 2026-08-27 13:29 KST

### DNS transaction report inventory

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- Completed matched DNS transactions now emit a bounded observation containing transaction ID, request/response packet indices, client, and server. The PCAP profile produces an explicit informational finding so reports surface the provenance rather than only raw TXT fragments.
- Verified with `python -m compileall -q src tests` and `DNS transaction inventory smoke passed`.

### Next

- Add Engine/report regression proving the persisted DNS transaction inventory and profile finding reach report.json.

## 2026-08-27 13:24 KST

### DNS transaction expiry regression

- Changed `tests/test_pcap_reassembly.py`.
- Added a 4,096-packet gap between an otherwise matching DNS request and TXT response. The bounded parser does not attach the stale request packet to the later response.
- Verified with `python -m compileall -q src tests` and `DNS transaction expiry smoke passed`.

### Next

- Add a concise bounded DNS transaction inventory for reports and evidence-backed PCAP findings.

## 2026-08-27 13:20 KST

### DNS TXT transaction-isolation regression

- Changed `tests/test_pcap_reassembly.py`.
- Added same-endpoint TXT responses with two different transaction IDs whose strings would form a valid-looking payload if incorrectly concatenated. Native reassembly correctly emits no combined output.
- Verified with `python -m compileall -q src tests` and `DNS TXT transaction isolation smoke passed`.

### Next

- Add a stale transaction-ID reuse expiry regression, then move to the next high-value parsing feature.

## 2026-08-27 13:17 KST

### DNS transaction bounds and TXT isolation

- Changed `src/forensickit/pcap.py`.
- Request entries are consumed after a matching response and expire after 4,096 packets. TXT reconstruction now groups by request packet when available, otherwise by transaction ID, in addition to endpoint direction; this prevents unrelated responses from the same DNS server being joined.
- Verified with `python -m compileall -q src tests` and direct transaction/TXT reconstruction smokes: `DNS transaction-bound TXT reconstruction smokes passed`.

### Next

- Add a same-endpoint, different-transaction regression proving TXT fragments cannot cross transaction boundaries.

## 2026-08-27 13:12 KST

### Exact DNS transaction provenance

- Changed `src/forensickit/pcap.py` and `tests/test_pcap_reassembly.py`.
- DNS requests are now indexed by the complete source/destination IPs, UDP ports, and transaction ID. A TXT-bearing response receives `request_packet_index` only when the complete inverse tuple matches; this preserves request-to-response provenance without parsing external state.
- Verified with `python -m compileall -q src tests` and a synthetic IPv6 request/response pair: `DNS transaction provenance smoke passed`.

### Next

- Bound request correlation lifetime so a reused DNS transaction ID cannot link an unrelated, later response.

## 2026-08-27 13:06 KST

### DNS query-label hex reconstruction

- Changed `src/forensickit/pcap.py`, `src/forensickit/engine.py`, and `tests/test_pcap_reassembly.py`.
- Hex-shaped DNS query-label streams are now decoded before Base64 to avoid ambiguous alphanumeric text being misclassified. Flag candidates retain `dns_label_fragment_reassembly → hex` provenance.
- Verified with `python -m compileall -q src tests` and direct Base64/hex DNS label Engine smokes: `DNS label Base64/hex reconstruction smokes passed`.

### Next

- Correlate DNS request/response transactions by exact endpoint/port/ID before enriching TXT provenance.

## 2026-08-27 13:02 KST

### DNS query-label reconstruction

- Changed `src/forensickit/pcap.py`, `src/forensickit/engine.py`, and `tests/test_pcap_reassembly.py`.
- Bounded DNS query fragments now preserve leftmost label, suffix, endpoint pair, and packet index. Only labels with the same endpoint pair and suffix are joined; successful Base64 reconstruction feeds FlagHunter with a distinct `dns_label_fragment_reassembly → base64` transform chain.
- Verified with `python -m compileall -q src tests` and an IPv6 two-query Engine smoke: `DNS label reconstruction flag smoke passed`.

### Next

- Add bounded hexadecimal DNS label reconstruction using the same provenance safeguards.

## 2026-08-27 12:54 KST

### DNS TXT reconstructed flag lineage

- Changed `src/forensickit/engine.py` and `tests/test_pcap_reassembly.py`.
- Base64-decoded DNS TXT reconstruction bytes now enter the normal bounded FlagHunter path. Candidate provenance records the exact endpoint pair and packet indices, and the transform chain starts with `dns_txt_fragment_reassembly → base64`.
- Verified with `python -m compileall -q src tests` and the two-packet PCAP Engine smoke: `DNS TXT reconstruction and flag lineage smoke passed`.

### Next

- Add bounded DNS label fragment reconstruction with query-packet provenance.

## 2026-08-27 12:51 KST

### DNS TXT fragment reconstruction

- Changed `src/forensickit/pcap.py`, `src/forensickit/profiles/pcap.py`, and `tests/test_pcap_reassembly.py`.
- DNS TXT records that are adjacent, bounded, and encoding-shaped are now grouped only by exact source/destination pair, with every source packet index retained. Base64 decoding is attempted only on the bounded joined string; the Pcap profile emits a cautious provenance-bearing lead when it succeeds. Ordinary TXT observations remain unchanged.
- Verified with `python -m compileall -q src tests` and a two-packet IPv6 DNS TXT fixture: `DNS TXT fragment reconstruction smoke passed`.

### Next

- Feed decoded DNS TXT reconstruction bytes into the existing FlagHunter without losing the endpoint/packet transform provenance.

## 2026-08-27 12:47 KST

### Staged offline bundle preflight

- Changed `scripts/install_offline.sh` and `README.md`.
- Added `--verify-only` to validate a bundle's required source archive, ForensicKit wheel, safe relative checksum paths, SHA-256 manifest, and target distro/architecture warning before any package, venv, or system mutation. The installer now rejects malformed bundles earlier.
- Verified shell syntax and a locally staged, no-network wheel/source bundle. A valid bundle passed `--verify-only`; appending bytes to its source archive made checksum validation fail as expected. The staged temporary bundle remains at `/tmp/forensickit-stage-v9lc7L` for audit.

### Next

- Implement bounded DNS TXT fragment reconstruction with packet-level provenance; Textual remains environment-blocked because its offline package is not installed.

## 2026-08-27 12:43 KST

### Offline pytest fallback

- Added `scripts/run_direct_tests.py`.
- The runner imports the repository's synthetic test modules without pytest, supports their current `tmp_path` and generator-backed `case_artifact` fixtures, and fails explicitly for any unsupported fixture instead of omitting a test.
- Confirmed no pytest wheel/cache is staged in this workspace. Verified `python -m compileall -q src tests scripts` and `python scripts/run_direct_tests.py`: `119 passed, 0 failed`.

### Next

- Validate the Textual UI only when its offline dependency is installed; otherwise improve and locally stage-check the offline-bundle installer.

## 2026-08-27 12:41 KST

### PID-scoped Volatility module/handle correlation

- Changed `src/forensickit/profiles/memory.py` and `tests/test_engine_pipeline.py`.
- Normalized Volatility DLLList `Path` rows now correlate only with File/Section Handle `Name`/`Path` rows that have the same PID and the same canonicalized complete path. The bounded `memory.process_correlations` observation retains exact matching rows, and a cautious `memory_module_handle_correlation_lead` finding records the evidence.
- Verified with `python -m compileall -q src tests` and a direct Engine fixture: `Volatility PID-scoped handle/DLL correlation engine integration test passed`.

### Next

- Check whether an offline pytest wheel is staged; if not, run the fixture-aware direct regression fallback and advance to staged offline-bundle validation.

## 2026-08-27 12:39 KST

### Generated PDF-output integration paths

- Changed `src/forensickit/tools/runner.py` and `tests/test_engine_pipeline.py`.
- Poppler `pdfdetach` and `pdfimages` generated outputs now have typed, bounded PDF inventories and normalized recovery findings before normal child-artifact registration. The engine fixtures verify both `pdfdetach` cwd attachment writes and `pdfimages` output-prefix writes, exact tool-run provenance, recursive child triage, and Base64 flag recovery.
- Verified with `python -m compileall -q src tests` and two direct Engine integration fixtures: `2 PDF generated-output engine integration tests passed`.

### iOS Manifest.db semantic routing

- Changed `src/forensickit/profiles/mobile.py` and `tests/test_engine_pipeline.py`.
- Native detection of Manifest.db/Info.plist now activates the Mobile profile even while the artifact's primary type remains SQLite or plist. Bounded fixed-column `fileID`/`domain`/`relativePath` references produce specific Messages, call-history, Safari, Notes, location, Wi-Fi, and Keychain collection leads; opaque `file` BLOBs are explicitly ignored.
- Verified with compileall and a direct SQLite Manifest.db Engine fixture containing opaque BLOB data: `iOS Manifest semantic-path engine integration test passed`.

### Next

- Add Volatility DLL/handle-to-process correlation using the existing normalized PID rows and a process-aware Engine fixture.

## 2026-08-27 11:30 KST

### Minidump metadata expansion

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/memory.py`, and `tests/test_triage.py`.
- Added bounded parsing of self-contained `MINIDUMP_HANDLE_DATA_STREAM` and `MINIDUMP_UNLOADED_MODULE_LIST` descriptors. String RVAs are validated; no process-memory object is dereferenced.
- Added evidence-backed findings for File/Section handles and unloaded modules in user-writable paths.
- Verified with `python -m compileall -q src tests` and a direct synthetic test invocation.

### Evidence-bundle ingestion

- Changed `src/forensickit/engine.py`, `tests/test_engine_pipeline.py`, and `README.md`.
- Explicit directory inputs now enumerate only regular non-symlink files in deterministic order, enforce `max_artifact_count`, preserve each as root evidence, and permit existing iOS Manifest.db correlation to link hashed payloads without inferred paths.
- Verified with compileall, a direct iOS backup directory E2E, and `python -m forensickit --help`.

### Next

- Add iOS Manifest.db payload-child promotion for explicitly supplied backup bundles while retaining both original-root and correlation provenance.

### Registry transaction-log provenance

- Changed `src/forensickit/engine.py` and `tests/test_engine_pipeline.py`.
- Exact root logical-name matching now links a Registry hive only to supplied sibling `.LOG1`/`.LOG2` files. Both directions receive observations and the hive receives a recovery-ready finding; no file is replayed, modified, or found by an implicit filesystem search.
- Verified with compileall and an isolated Registry directory-bundle smoke, plus an iOS directory-bundle regression.

### Volatility memory expansion

- Changed `src/forensickit/tools/registry.py`, `config/tool-catalog.yaml`, `src/forensickit/tools/parsers.py`, `src/forensickit/profiles/memory.py`, and `tests/test_tools.py`.
- Added bounded deep plans for Windows PsScan, Handles, and FileScan. Parser output now preserves those tables and uses PsList/PsScan PID differences for a cautious hidden-process lead.
- Verified with compileall, standalone parser/profile assertions, and an argv construction smoke using a temporary executable. `tests/test_tools.py` cannot be imported wholesale in this environment because pytest is absent.

### Offline bundle scripts

- Added `scripts/build_offline_bundle.sh` and `scripts/install_offline.sh`; updated `README.md`.
- The builder creates a same-distro/architecture source, wheel, optional Debian package, optional approved-tool-tree bundle and SHA-256 manifest. The installer verifies the manifest and uses only `pip --no-index` and `apt-get --no-download`.
- Verified shell syntax, executable entry points, both help paths, and compileall. The initial installer help invocation exposed a positional-argument parsing defect, which was fixed before recording this result.

### Windows LNK LinkInfo

- Changed `src/forensickit/triage.py`, `src/forensickit/profiles/windows.py`, and `tests/test_triage.py`.
- Added bounded LinkInfo header/offset validation and ANSI/Unicode local-base/common-suffix recovery. Reconstructed target paths are metadata only and are never opened or executed.
- Verified with compileall and a synthetic Unicode LinkInfo path/profile smoke.

### Offline bundle doctor validation

- Changed `src/forensickit/doctor.py`, `src/forensickit/cli.py`, `tests/test_workspace_extraction.py`, and `README.md`.
- Added `forensickit doctor --bundle PATH`, which validates staged source/wheel/manifest structure and every SHA-256 entry without network access. Missing bundle input retains a clear preparation warning rather than changing required-runtime health.
- Verified compileall, a valid synthetic bundle, the CLI help path, and an actual doctor invocation. Added a checksum-mismatch regression for the next verification pass.

### Bundle compatibility and Volatility DLL/VAD expansion

- Changed `src/forensickit/doctor.py` and `tests/test_workspace_extraction.py` so a hash-valid staged bundle warns before installation when its manifest architecture/distro target differs from the current host. Valid, corrupt, and target-mismatch synthetic bundle smokes pass.
- Changed `src/forensickit/tools/registry.py`, `config/tool-catalog.yaml`, `src/forensickit/tools/parsers.py`, `src/forensickit/profiles/memory.py`, and `tests/test_tools.py`.
- Added deep Windows DLLList and Malfind plans, bounded table normalization, and cautious module/VAD findings. Compileall plus standalone parser/profile smoke passed.

### Direct regression sweep and FileScan dump follow-up

- Ran all pytest-independent test modules through a direct fixture-aware runner: 97 synthetic smokes passed. A minimal local `pytest.fixture` shim then ran all 15 `test_tools.py` regressions; total direct result: 112 passed, 0 skipped.
- Changed `src/forensickit/tools/registry.py`, `config/tool-catalog.yaml`, and `src/forensickit/profiles/memory.py`.
- Each validated hexadecimal FileScan object offset can now produce a separate DEEP `windows.dumpfiles.DumpFiles --physaddr` plan (maximum 16), retaining the offset as command provenance. DumpFiles is marked as generated-output capable, so emitted bytes use the existing bounded recursive child-artifact path.
- Verified compileall plus parameterized follow-up planning and argv smoke.

### Volatility generated-child Engine E2E

- Changed `tests/test_engine_pipeline.py`.
- Added a synthetic `vol` executable that emits a FileScan row, then writes a Base64 payload when the Engine's second-generation decision invokes DumpFiles with the parser-derived physical file-object offset.
- Verified `python -m compileall -q src tests` and the direct E2E: exact `--physaddr 0x1234` argv, DumpFiles tool-run ID on `dumped.bin`, recursive analysis, and `CTF{volatility_dumpfiles}` candidate all pass.

### Process-aware Volatility correlation

- Changed `src/forensickit/profiles/base.py`, `src/forensickit/profiles/__init__.py`, `src/forensickit/engine.py`, and `src/forensickit/profiles/memory.py`.
- Profile-produced observations are now persisted alongside findings/recommendations. The Memory profile joins normalized Volatility rows by PID into bounded `memory.process_correlations` records and emits a cautious multi-class correlation finding only when at least three supporting artifact classes overlap.
- Verified compileall and a synthetic PID 444 process/command/network/module correlation smoke.

### Process-correlation Engine/report E2E

- Changed `tests/test_engine_pipeline.py` and corrected aggregation in `src/forensickit/profiles/memory.py`.
- Added a synthetic multi-plugin Volatility E2E covering PsList, CmdLine, NetScan, and DLLList. The Engine's second decision persists `memory.process_correlations`, emits `memory_process_correlation_lead`, and renders the observation in report.json.
- The first E2E exposed empty per-plugin default observations masking later populated rows via `next()`; correlation now aggregates every matching normalized observation list. Compileall and the repaired Engine/report E2E pass.

### iOS Manifest payload-reference expansion

- Changed `src/forensickit/triage.py`, `src/forensickit/engine.py`, and `tests/test_engine_pipeline.py`.
- Manifest.db fixed-column read-only inventory now keeps up to 1,000 exact file-ID/domain/relative-path references (with an explicit truncation observation). Case correlation prefers this inventory over the 200-row UI summary, preserving deduplicated supplied payload roots rather than creating misleading duplicate children.
- Verified compileall and an iOS backup E2E in which the only supplied payload matches the 201st Manifest `Files` row.
