# ForensicKit v1.2.0

> 인터넷과 AI 없이도 CTF 증거 파일을 **보존 → 식별 → 분석 → 추출 → 재귀 분석 → 플래그 탐색 → 보고서 생성**까지 처리하는 로컬 디지털 포렌식 오케스트레이터입니다.

ForensicKit은 단순 명령어 래퍼가 아닙니다. 확장자를 믿지 않고 파일 구조와 시그니처를 확인한 뒤 어떤 도구를 왜 실행할지 결정합니다. 추출된 자식 파일도 안전 한도 안에서 다시 분석하며, 모든 결과를 원본까지 추적할 수 있게 기록합니다.

- 외부 API, LLM, Docker, 런타임 네트워크 연결 없이 완전 오프라인 동작
- 원본을 덮어쓰거나 실행하지 않고 읽기 전용 사본을 분석
- 도구가 없거나 실패해도 전체 분석을 중단하지 않음
- 해시, 정확한 argv, stdout/stderr, 추출 계보를 SQLite와 보고서에 보존

## 30초 시작

Python 3.12 이상에서 저장소 루트에서 딱 세 줄만 실행하세요.

```bash
python3 -m pip install .
forensickit doctor
forensickit self-test
forensickit analyze /path/to/challenge.bin --auto
```

터미널의 `[FLAG]`가 플래그 후보입니다. 마지막에 출력된 `Report:`의 `report.md`가 사람이 읽는 최종 보고서이고, 같은 사건 폴더에 원본 사본·추출물·도구 원문 출력이 모두 보존됩니다.

| 상황 | 명령 |
| --- | --- |
| 빠른 내장 점검만 | `forensickit triage FILE` |
| 추천 도구와 이유만 | `forensickit recommend FILE` |
| 일반 대회 분석 | `forensickit analyze FILE --auto` |
| 오래 걸리는 carving/stego 포함 | `forensickit analyze FILE --deep` |
| 실행 없이 계획만 | `forensickit analyze FILE --plan` |

처음이면 `doctor` 후 `--auto`를 쓰면 됩니다. 못 찾았을 때만 `--deep`으로 올리세요. 전체 옵션은 `forensickit --help`와 `forensickit analyze --help`로 확인할 수 있습니다.

`forensickit self-test`는 외부 도구나 네트워크 없이 임시 합성 증거를
보존하고, PNG 뒤 ZIP을 추출해 Base64 플래그를 재귀 탐색한 뒤 SQLite와
JSON/Markdown/HTML 보고서까지 검증합니다. 대회 직전 `doctor` 다음에
실행하면 설치된 핵심 런타임 자체가 온전한지 확인할 수 있습니다.

Maintainers close a release with `scripts/release_gate.sh --bundle BUNDLE`.
The gate refuses a dirty tree and runs compile/shell checks, the full pytest
suite, the installed-core self-test, Doctor bundle validation, and installer
verification without network access. `--allow-dirty` produces development-only
evidence and never constitutes a releasable result.

## Competition quick start

Check the workstation before a challenge:

```bash
forensickit doctor
```

Validate copied offline media before competition time:

```bash
forensickit doctor --bundle /media/usb/forensickit-bundle
```

Analyze one file without executing external tools:

```bash
forensickit analyze challenge.bin
```

Run justified available tools and recursively inspect extracted content:

```bash
forensickit analyze challenge.bin --auto
```

Add optional search conditions without changing the default `CTF{...}` and
`FLAG{...}` candidate hunt:

```bash
forensickit analyze evidence/ --auto \
  --flag-prefix 'ACME' \
  --exact-string 'Account=Alice' \
  --search-term 'example.test' \
  --regex 'ticket-[0-9]{4}'
```

`--flag-prefix` creates a bounded `PREFIX{...}` candidate format,
`--exact-string` is case-sensitive, and `--search-term` is a case-insensitive
filename/content clue. `--regex` is the explicit advanced mode: lookarounds,
backreferences, nested repetition, and repeated alternation are rejected, and
each match operation has a timeout. Matches remain candidates/leads for analyst
validation; ForensicKit never marks a discovered string as the answer.

Use expensive/carving-oriented paths when time and resources permit:

```bash
forensickit analyze challenge.bin --deep
```

Preview the exact local tool plan without running commands:

```bash
forensickit analyze challenge.bin --plan
```

Several supplied artifacts can share one case (for example a disk image and sidecar logs):

```bash
forensickit analyze disk.E01 notes.txt Manifest.db --auto
```

For a full Windows memory image, deep mode can additionally extract selected
process memory/modules. A user-mode `MDMP` minidump is recognized separately
and is not sent through full-system PsList/PsScan/NetScan/FileScan plans.

```bash
forensickit analyze memory.raw --deep --pid 444 --pid 1337
```

The installed Volatility 3 build and offline symbol cache determine which
images are actually supported; `forensickit doctor` reports both. The engine
records symbol-missing, image/layer mismatch, unsupported plugin/argument, and
ordinary plugin failure separately. FileScan physical object addresses use
`windows.dumpfiles.DumpFiles --physaddr`; they are never labelled as file
offsets or virtual addresses.

An explicitly supplied evidence directory is treated as a bounded bundle of
immutable root files. This is useful for an iOS backup folder: `Manifest.db`
and its 40-hex payload files are ingested, analyzed, and exactly correlated
without following symlinks or guessing paths.

```bash
forensickit analyze /evidence/ios-backup --auto
```

The terminal output highlights findings and `[FLAG]` candidates. The complete, reproducible record is stored in the printed case workspace:

```text
case/
├── evidence/       # immutable copies of supplied root evidence
├── extracted/      # bounded child artifacts, linked to parent/tool run
├── outputs/        # raw stdout
├── logs/           # raw stderr
├── reports/
│   ├── report.json
│   ├── report.md
│   ├── report.html  # dependency-free, evidence strings HTML-escaped
│   ├── timeline.csv # normalized, provenance-bearing event timeline when available
│   └── search_results.csv # one row per preserved flag/search location
└── case.db
```

Review a completed case headlessly:

```bash
forensickit artifacts cases/<case-directory>
forensickit findings cases/<case-directory>
forensickit flags cases/<case-directory>
forensickit search-hits cases/<case-directory>
forensickit errors cases/<case-directory>
forensickit report cases/<case-directory>
```

`report.json` and `report.md` include the normalized timeline. `timeline.csv`
provides the same bounded event rows with artifact, EventRecordID/native byte
offset, activity-cluster score, parser observation, tool-run, and raw stdout
provenance. Spreadsheet formula-like evidence values are escaped only in CSV;
their original values remain unchanged in JSON and the case database.

Windows directory bundles can include EVTX, Registry hives and logs, LNK,
Prefetch, Recycle Bin pairs, Jump Lists, NTFS metadata, and browser databases.
Automatic/Custom Destinations are structurally validated and embedded LNKs
re-enter recursive analysis. Known Chromium/Firefox/Safari SQLite schemas are
queried read-only; an exactly named, separately supplied `History-wal` is
applied only in an isolated case-cache snapshot. Browser and Jump List records
retain raw timestamps/epoch semantics and are included in `timeline.csv`.
Fixed Registry paths also recover bounded modern Amcache application/file
inventory and 00ts/10ts AppCompatCache (Shimcache) entries. Records retain hive
cell/value offsets and raw FILETIMEs, re-enter common search, and can be joined
across independently supplied artifacts only by an exact normalized Windows
path. Cache presence and cache timestamps are leads, not proof of execution.

`textual` is included in the standard ForensicKit installation, so
`forensickit` starts the keyboard-first analysis UI; `forensickit tui
cases/<case-directory>` can also
open a completed or partial case. Enter an evidence file/directory, optional
flag prefix/exact string/search term (or explicitly enable advanced regex),
choose Quick/Automatic/Deep/Plan, and press **Analyze**. Analysis runs on a
worker thread while progress and completed artifact/tool results appear. The
UI provides cancel and whole-analysis retry, summary/flag/memory/Windows/
timeline/extraction/log/search/next-action tabs, time/PID/user/path/text
filters, display-timezone conversion, candidate copy, bounded raw-log preview,
and explicit extracted-file saving. `Ctrl+R` refreshes, `Ctrl+C` cancels, `c`
copies a selected candidate, and `q` exits after requesting cancellation.

Before copying a staged bundle to a competition workstation, or before installing it there, validate its local manifest without touching the system:

```bash
scripts/install_offline.sh /media/forensickit-offline-bundle --verify-only
```

## Offline installation

Bootstrap a prepared Ubuntu/Kali workstation before competition time:

```bash
chmod +x install_forensics.sh
sudo ./install_forensics.sh --full
```

The script installs a local Python toolbox including PyYAML and Textual, then attempts the optional external forensic tools. Re-run `forensickit doctor` after installation: missing optional tools are reported and are safely skipped by planning/execution.

For a Python package environment, install the UI and test extras from already staged wheels when offline:

```bash
python -m pip install '.[tui,test]'
```

To prepare a same-distro, same-architecture competition machine while online,
build a verified local bundle (including wheels and a selected Debian package
set), then install it without network access:

```bash
scripts/build_offline_bundle.sh --output /media/usb/forensickit-bundle
scripts/install_offline.sh /media/usb/forensickit-bundle --link-bin
forensickit doctor
```

Release bundles are refused when the source worktree is dirty and record the
exact source commit in their build manifest. `--allow-dirty` is available only
for explicitly disposable development bundles. Installation refuses a
non-empty prefix unless `--upgrade` is supplied; upgrades force-reinstall the
single checksummed ForensicKit wheel so an older same-version install cannot be
silently reused.

When adding a prepared tool/symbol tree, copy and complete the supplied
component metadata template first. Every regular file in the tree must be
covered by a declared component; symlinks and special files are refused.

```bash
cp config/offline-components.example.json /tmp/offline-components.json
# Fill in tested versions, applicable licenses/terms, source, OS, architecture, and paths.
scripts/build_offline_bundle.sh \
  --output /media/usb/forensickit-bundle \
  --tools-root /opt/prepared-forensic-tools \
  --components-metadata /tmp/offline-components.json
```

The v2 bundle includes `manifests/component-manifest.json`: source, Python
wheels, Debian packages, rules/catalogs, and prepared tools/symbols retain
versions, license metadata/reference, supported environment, sizes, and
SHA-256 identities. `SHA256SUMS`, `install_offline.sh --verify-only`, and
`forensickit doctor --bundle ...` independently reject unsafe paths or changed
payloads. A missing/`NOASSERTION` license is surfaced as a readiness warning;
it is never silently replaced with an invented license.

The bundle installer verifies SHA-256 checksums, uses `pip --no-index` and
`apt-get --no-download`, and warns on distro-version mismatch. Use
`--tools-root /opt/forensic-tools` when the preparer already has an approved
local tools/symbol tree to carry alongside the Python runtime.

## Safety and scope

- Original evidence is copied once into the case workspace and made read-only.
- All external commands use argv arrays (no shell interpolation), a timeout, and preserved stdout/stderr.
- Volatility commands are forced to use global `--offline`, quiet JSON output,
  and the tool run's case-scoped output directory. `doctor` probes the staged
  framework version and verifies the exact Info/process/network/extraction
  plugins and arguments used by the memory workflow.
- `Ctrl-C` requests graceful cancellation; active process groups are stopped
  and their run state is recorded as `canceled`. CLI status lines are emitted
  while artifacts and tools run.
- Defaults for a 4-vCPU/16-GiB workstation are `--jobs 2`,
  `--memory-jobs 1`, a 6-GiB per-tool address-space ceiling, and a 2-GiB
  per-generated-file ceiling. Override them with `--jobs`, `--memory-jobs`,
  `--tool-memory-bytes`, and `--tool-output-bytes`; Linux enforces the latter
  two with process resource limits.
- Recursive extraction is capped by depth, artifact count, per-child size, and cumulative bytes.
- File search is chunked (1 MiB by default) with a 16 KiB default overlap,
  a 4,096-character maximum match, 2 GiB byte ceiling, three transform levels,
  2,000 decoded regions, 64 MiB decoded output, and a 20-second per-source
  deadline. These limits are recorded in `search.scan_summary`; decoded results
  retain their encoded source range and never claim a derived offset is an
  original evidence offset.
  `--max-search-bytes`, `--search-timeout`, and `--decode-depth` tune the main
  search bounds for the available competition workstation.
- A detected flag is a candidate with source, offset/location where available, and transform chain—not an unsupported assertion of correctness.

See [AGENTS.md](AGENTS.md) for the investigation model and [TOOL_CATALOG.md](TOOL_CATALOG.md) for integrated tools.
