# ForensicKit v1.0.0

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
│   └── timeline.csv # normalized, provenance-bearing event timeline when available
└── case.db
```

Review a completed case headlessly:

```bash
forensickit artifacts cases/<case-directory>
forensickit findings cases/<case-directory>
forensickit flags cases/<case-directory>
forensickit errors cases/<case-directory>
forensickit report cases/<case-directory>
```

`report.json` and `report.md` include the normalized timeline. `timeline.csv`
provides the same bounded event rows with artifact, EventRecordID/native byte
offset, activity-cluster score, parser observation, tool-run, and raw stdout
provenance. Spreadsheet formula-like evidence values are escaped only in CSV;
their original values remain unchanged in JSON and the case database.

With the offline `textual` package installed, `forensickit` starts the keyboard-first case viewer; `forensickit tui cases/<case-directory>` opens a specific case. `r` refreshes and `q` exits. The viewer is read-only and displays artifacts, findings, tool runs/raw-output paths, and flag candidates.

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

The bundle installer verifies SHA-256 checksums, uses `pip --no-index` and
`apt-get --no-download`, and warns on distro-version mismatch. Use
`--tools-root /opt/forensic-tools` when the preparer already has an approved
local tools/symbol tree to carry alongside the Python runtime.

## Safety and scope

- Original evidence is copied once into the case workspace and made read-only.
- All external commands use argv arrays (no shell interpolation), a timeout, and preserved stdout/stderr.
- Recursive extraction is capped by depth, artifact count, per-child size, and cumulative bytes.
- A detected flag is a candidate with source, offset/location where available, and transform chain—not an unsupported assertion of correctness.

See [AGENTS.md](AGENTS.md) for the investigation model and [TOOL_CATALOG.md](TOOL_CATALOG.md) for integrated tools.
