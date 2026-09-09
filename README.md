# ForensicKit v1.2.0

> 인터넷, 외부 API, AI/LLM, Docker 없이 로컬 증거를 **보존 → 식별 → 관찰 → 가설 → 검증 → 발견 → 보고**하는 오프라인 우선 CTF 디지털 포렌식 오케스트레이터입니다.

ForensicKit은 파일 확장자만 보고 정해진 명령을 실행하는 래퍼가 아닙니다. 증거의 해시·시그니처·구조를 먼저 확인하고, 분석 프로필과 규칙으로 어떤 도구를 왜 실행할지 계획합니다. 추출된 자식 파일도 정해진 한도 안에서 다시 분석하며, 플래그 후보와 발견 사항이 어느 원본·오프셋·변환·도구 출력에서 나왔는지 사건 데이터베이스와 보고서에 남깁니다.

주요 운영 원칙은 다음과 같습니다.

- 제출된 증거를 사건 폴더로 복사하고 SHA-256을 계산한 뒤 읽기 전용으로 보존합니다. 원본을 덮어쓰거나 프로그램으로 실행하지 않습니다.
- 런타임 분석은 네트워크 요청, 외부 API, LLM을 사용하지 않습니다. 단, 사전 설치와 번들 생성 스크립트는 온라인 준비 단계에서 패키지와 도구를 내려받을 수 있습니다.
- 외부 명령은 셸 문자열이 아닌 argv 배열로 실행하고, 시간·메모리·출력 크기를 제한하며 stdout/stderr와 종료 상태를 보존합니다.
- 선택 도구가 없거나 실패해도 사건 전체를 중단하지 않고 오류와 미검증 상태를 기록합니다.
- 발견된 문자열은 어디까지나 `candidate`입니다. ForensicKit이 대회 정답이라고 단정하지 않으므로 분석가가 문맥과 계보를 최종 확인해야 합니다.

## 30초 시작

요구 사항은 Linux와 Python 3.12 이상입니다. 저장소 루트에서 다음을 실행합니다.

```bash
python3 -m pip install .
forensickit doctor
forensickit self-test
forensickit analyze /path/to/challenge.bin --auto
```

배포판의 시스템 Python이 직접 설치를 막는 경우 가상 환경을 사용합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

분석이 끝나면 터미널의 `[FLAG]` 항목을 우선 확인하고, 마지막 `Report:` 경로의 `report.md`를 엽니다. 원본 보존 사본, 추출물, 도구 원문 출력, 데이터베이스와 다른 형식의 보고서도 같은 사건 폴더에 있습니다.

| 목적 | 명령 | 외부 도구 실행 |
| --- | --- | --- |
| 빠른 내장 점검 | `forensickit triage FILE` | 안 함 |
| 추천 도구와 이유 확인 | `forensickit recommend FILE` | 안 함 |
| 일반 대회 분석 | `forensickit analyze FILE --auto` | 정당화되고 설치된 도구만 실행 |
| carving·stego·메모리 심층 분석 | `forensickit analyze FILE --deep` | 비용이 큰 계획까지 실행 가능 |
| 실제 실행 전 계획 확인 | `forensickit analyze FILE --plan` | 안 함 |

처음에는 `doctor`와 `self-test`를 통과시킨 뒤 `--auto`를 사용하고, 단서가 부족하거나 시간이 충분할 때만 `--deep`으로 올리는 흐름을 권장합니다. `self-test`는 외부 도구와 네트워크 없이 합성 증거 보존, PNG 뒤 ZIP 추출, Base64 플래그 재귀 탐색, SQLite 및 JSON/Markdown/HTML 보고서 생성을 점검합니다.

## 동작 방식과 아키텍처

조사 모델은 항상 다음 순서를 따릅니다.

```text
증거(Evidence)
  → 관찰(Observation)
  → 가설(Hypothesis)
  → 검증(Verification)
  → 발견(Finding)
  → 보고서와 아티팩트 그래프
```

핵심 구성 요소는 역할별로 분리되어 있습니다.

| 계층 | 역할 | 주요 구현 위치 |
| --- | --- | --- |
| 사건·증거 관리 | 사건 폴더 생성, SHA-256, 원본 사본, SQLite 등록 | `workspace.py`, `evidence.py`, `storage.py` |
| 식별·초기 분석 | 확장자 대신 매직 바이트, MIME, 구조, 문자열, 엔트로피를 조합 | `triage.py`, `identification.py` |
| 의사결정 | 증거 유형별 프로필, 규칙, 도구 추천 이유와 우선순위 생성 | `profiles/`, `rules.py`, `planner.py` |
| 안전 실행 | 로컬 실행 파일 탐지, argv 생성, 동시성·시간·자원 제한, 결과 파싱 | `tools/registry.py`, `tools/runner.py`, `tools/parsers.py` |
| 추출·재귀 | 내장 컨테이너/파일시스템 추출, 도구 생성물 등록, 부모-자식 계보 | `extraction.py`, `graph.py` |
| 검색·상관 분석 | 플래그/문자열/정규식 검색, 디코딩, Windows·메모리·경로 상관 분석 | `flags.py`, `engine.py` |
| 사용자 인터페이스 | 명령행, 키보드 중심 TUI, 설치 상태 진단 | `cli.py`, `tui.py`, `doctor.py` |
| 보고 | JSON, Markdown, HTML, 타임라인·검색 CSV 생성 | `reporting.py` |

한 파일은 여러 분류를 동시에 가질 수 있습니다. 선택된 주 분류뿐 아니라 대체 분류와 그 근거도 저장되며, 여러 루트 증거를 한 사건으로 넣으면 명시적으로 확인 가능한 경로·PID·시간 등의 공통 키만으로 상관 분석합니다.

## 기술 스택

현재 저장소가 실제로 사용하는 런타임 스택은 다음과 같습니다.

- Python 3.12 이상
- 표준 라이브러리 기반 `argparse` CLI, 해시·압축·아카이브·구조 파서
- SQLite 사건 데이터베이스
- PyYAML: 선언형 도구 카탈로그와 규칙 로드
- Textual: 키보드 중심 터미널 UI
- pytest: 자동 테스트
- Bash: Ubuntu/Kali 온라인 설치, 오프라인 번들 생성·검증·설치, 릴리스 게이트
- 로컬 네이티브 도구: libmagic/file, ExifTool, 7-Zip, tshark, Sleuth Kit, Volatility 3 등. 모두 선택 사항이며 설치 여부에 따라 계획에서 사용 또는 누락 처리됩니다.

도구 정의는 `config/tool-catalog.yaml`, 분석 규칙 예시는 `config/rules.example.yaml`에 있습니다. 통합 대상의 전체 우선순위는 [TOOL_CATALOG.md](TOOL_CATALOG.md), 내장 범위는 [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md)를 참고하십시오.

## 지원 증거 유형과 도구의 역할

내장 분석기는 인터넷과 외부 도구가 없어도 제한된 범위의 식별·구조 검증·추출·검색을 수행합니다. 외부 도구는 형식별 전문 검증과 더 넓은 열거를 보완합니다. 아래의 “지원”은 모든 손상 사례를 완전 복구한다는 뜻이 아니라, 안전 한도 안에서 처리하고 근거를 남긴다는 뜻입니다.

| 증거 유형 | 내장 처리 | 외부 도구의 보완 역할 |
| --- | --- | --- |
| 일반 파일·플래그 | SHA-256, 시그니처/MIME, 문자열, 엔트로피, 임베디드 형식, Base64/Base32/hex·반복 디코딩 검색 | `file`, ExifTool, YARA, binwalk, 7-Zip |
| 이미지·스테가노그래피 | PNG/JPEG/GIF/TIFF/BMP 구조, JPEG EXIF/XMP/ICC/Photoshop 메타데이터, 뒤에 붙은 컨테이너 탐지와 재귀 분석 | `pngcheck`, `zsteg`, `steghide`, `stegseek`, `outguess`, carving 도구 |
| 아카이브·광학 이미지 | ZIP/TAR/gzip/bzip2/xz, CPIO, ISO 9660/Rock Ridge/Joliet/El Torito, UDF 구조와 제한적 안전 추출 | 7-Zip, binwalk, Sleuth Kit 및 carving 도구로 확장 검증 |
| 네트워크 캡처 | PCAP/PCAPNG, DNS/TLS 메타데이터, 제한된 HTTP·FTP·SMTP·POP3·IMAP·SMB2 재조립과 자식 파일 등록 | `tshark`, `capinfos`로 전체 프로토콜 분석과 내장 결과 교차 검증 |
| 디스크·파일시스템 | MBR/GPT/EBR, FAT12/16/32, exFAT, 제한된 ext2/3/4와 NTFS, 파티션 충돌·부트 구조·일부 파일 추출 | Sleuth Kit(`mmls`, `fsstat`, `fls`; 그 밖의 `icat`, `tsk_recover`는 별도 수동 사용), EWF 도구, TestDisk/PhotoRec |
| Windows 아티팩트 | EVTX, Registry hive/로그, LNK, Prefetch, Recycle Bin, Jump List, 브라우저 SQLite/WAL, NTFS/USN 일부, 타임라인·정확 경로 상관 분석 | RegRipper, Hayabusa, Chainsaw, Plaso 및 libyal 도구 |
| 메모리 | 전체 메모리와 `MDMP` 미니덤프 구분, 미니덤프 모듈·스레드·범위·핸들 메타데이터, Volatility 결과 정규화·상관 분석 | Volatility 3으로 OS/프로세스/명령행/네트워크/핸들/DLL/파일/악성 메모리 영역 분석과 선택 PID 추출 |
| 문서·실행 파일 | PDF/Office/PE/ELF 등 시그니처와 공통 구조·문자열 단서 | pdfinfo/pdftotext/qpdf/pdfid, oletools/oledump, readelf 등 |
| 모바일·펌웨어 | Android backup/APK/boot image, iOS `Info.plist`·`Manifest.db`와 정확한 40자리 해시 payload 연결, SquashFS/uImage 단서 | APKTool/JADX, ALEAPP/iLEAPP, UBI Reader, Jefferson 등 |

### UDF와 ISO 처리 시 주의점

UDF는 BEA/NSR/TEA, anchor, descriptor tag checksum/CRC, partition/LVD, main·reserve VDS, File Set Descriptor, Type-1 FE/EFE 및 FID 디렉터리 트리를 검증합니다. 변환이 필요 없고 범위와 할당 메타데이터를 다시 검증할 수 있는 완전한 embedded/short/long/extended allocation 파일만 자식으로 복사합니다. sparse 구간은 명시적으로 다루며, 링크·장치·특수 파일, 모호하거나 범위를 벗어난 항목, 불완전한 extent는 호스트에서 생성하지 않습니다.

ISO는 primary/Joliet/Rock Ridge 경로와 multi-extent, zisofs, El Torito의 제한된 구조를 다룹니다. 복잡하거나 손상된 광학 이미지의 완전 복구를 주장하지 않으므로 7-Zip 또는 Sleuth Kit 계열 결과와 비교해야 합니다.

### Windows 디렉터리 묶음

EVTX, Registry hive와 `.LOG1`/`.LOG2`, LNK, Prefetch, Jump List, 브라우저 데이터베이스 등을 한 디렉터리로 제공할 수 있습니다. Automatic/Custom Destinations는 구조를 검증하고 포함된 LNK를 재귀 분석합니다. Chromium/Firefox/Safari의 알려진 SQLite 스키마만 읽기 전용으로 조회하며, 정확한 이름의 별도 `History-wal`은 사건 캐시의 격리된 스냅샷에만 적용합니다.

Amcache와 00ts/10ts AppCompatCache(Shimcache), 브라우저, Jump List, EVTX, USN 등에서 얻은 시간과 원시 위치를 타임라인에 남깁니다. 캐시 존재나 캐시 타임스탬프는 실행 증명이 아니라 조사 단서입니다. 서로 따로 제출된 증거는 정확히 정규화된 Windows 경로처럼 검증 가능한 키가 일치할 때만 연결합니다.

```bash
forensickit analyze /evidence/windows-case --auto
```

### 메모리와 Volatility 3

전체 시스템 Windows 메모리의 자동 모드는 Info, PsList, PsTree, CmdLine, NetScan, Handles, DllList 등을 계획할 수 있고, 심층 모드는 PsScan, FileScan, Malfind와 선택 PID의 Memmap/DllList 추출을 추가할 수 있습니다. `MDMP` 사용자 모드 미니덤프는 별도로 인식되며 전체 시스템 PsList/PsScan/NetScan 계획에 넣지 않습니다.

```bash
forensickit analyze memory.raw --deep --pid 444 --pid 1337
```

`--pid`는 양의 32비트 정수이며 최대 16번 지정할 수 있습니다. 실제 지원 가능 이미지는 설치된 Volatility 3 버전과 이미지에 맞는 로컬 심볼에 따라 달라집니다. `doctor`는 `vol`/`vol.py`/`vol-offline`, `--offline`, JSON renderer, 사용 플러그인과 추출 인자, 심볼 캐시를 확인합니다. FileScan의 물리 객체 주소는 `windows.dumpfiles.DumpFiles --physaddr`로 전달하며 파일 오프셋이나 가상 주소라고 표시하지 않습니다.

## Ubuntu/Kali 온라인 사전 설치

### ForensicKit만 설치

의존성을 내려받을 수 있는 온라인 환경이라면 별도의 가상 환경 설치가 가장 단순합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[test]'
forensickit doctor
forensickit self-test
```

기본 설치에는 PyYAML과 Textual이 포함됩니다. `test` extra는 pytest를 추가하고, `tui` extra는 호환성을 위해 사용할 수 있지만 현재 별도 패키지를 더하지 않습니다.

### 포렌식 도구 상자 설치

Ubuntu 24.04/26.04 이상, Kali rolling 및 Debian 계열 준비 장비에서는 다음 스크립트를 대회 전에 온라인으로 실행할 수 있습니다.

```bash
chmod +x install_forensics.sh
sudo ./install_forensics.sh --full
```

선택 가능한 모드는 다음과 같습니다.

| 명령 | 동작 |
| --- | --- |
| `sudo ./install_forensics.sh --core` | 핵심 APT 도구와 Python 포렌식 도구 상자를 준비 |
| `sudo ./install_forensics.sh --full` | 기본값. GUI/대형 도구, 로컬 증거 암호 도우미, Volatility 심볼, Hayabusa/Chainsaw, ALEAPP/iLEAPP, 규칙 캐시까지 최선 노력으로 준비 |
| `./install_forensics.sh --doctor` | 설치를 변경하지 않고 알려진 명령의 탐지 결과만 출력 |

이 스크립트는 `apt`, `pip`, GitHub 릴리스와 Git 저장소에 접근하고 `/opt/forensic-tools`, `/usr/local/bin`, `/etc/profile.d/forensic-tools.sh`를 변경할 수 있습니다. 배포판 저장소에 없는 선택 패키지나 다운로드 실패는 경고 후 건너뜁니다. 따라서 성공 메시지만 믿지 말고 다음을 다시 실행하십시오.

```bash
forensickit tools
forensickit doctor
forensickit self-test
```

`install_forensics.sh`는 외부 도구 상자를 준비하는 스크립트입니다. 현재 ForensicKit 프로젝트 자체는 위의 `pip install .` 또는 아래 오프라인 번들 설치로 별도 설치해야 합니다.

## 오프라인 번들: 생성, 검증, 설치, 업그레이드

번들은 **실제 대회 장비와 같은 배포판 릴리스 및 같은 아키텍처**의 온라인 Ubuntu/Kali/Debian 계열 장비에서 만드십시오. Debian 패키지는 다른 릴리스나 아키텍처 사이의 호환성을 보장하지 않습니다.

### 1. 온라인 장비에서 생성

깨끗하게 커밋된 작업 트리에서 실행합니다. 출력 디렉터리가 이미 있으면 덮어쓰지 않고 거부합니다.

```bash
scripts/build_offline_bundle.sh \
  --output /media/usb/forensickit-bundle
```

기본 번들에는 ForensicKit 소스 스냅샷, ForensicKit과 Python 의존성 wheel, 테스트 의존성, 그리고 선별된 로컬 APT 패키지 세트가 들어갑니다. `pip wheel`과 APT 다운로드에는 네트워크, 저장소 메타데이터, 충분한 저장 공간이 필요합니다. 옵션은 다음과 같습니다.

- `--package NAME`: 번들에 Debian 패키지를 추가하며 반복 지정할 수 있습니다.
- `--no-apt`: wheel과 소스만 만들고 APT 패키지는 제외합니다.
- `--tools-root DIR --components-metadata FILE`: 미리 준비한 도구·심볼 트리와 그 메타데이터를 함께 넣습니다.
- `--allow-dirty`: 커밋되지 않은 변경이 있는 개발용 번들만 허용합니다. 릴리스 준비 완료의 근거가 될 수 없습니다.

생성된 디렉터리에는 독립 실행 가능한 `install_offline.sh`도 포함됩니다. 따라서 오프라인 장비에는 저장소 전체가 아니라 완성된 번들 디렉터리 하나만 복사해도 됩니다. Python wheel은 고정된 `SOURCE_DATE_EPOCH`로 만들고 `manifests/python-wheel-lock.json`에 실제로 해석된 배포 이름·버전·의존성·SHA-256을 기록합니다. 이 잠금 파일은 “한 배포 이름당 wheel 하나” 원칙을 강제하지만, 온라인 준비 시점에 더 새로운 의존성 버전을 선택하는 것 자체를 막는 버전 핀은 아닙니다. 최종 번들의 해시와 잠금 파일을 하나의 불변 배포물로 보관하십시오.

### 2. prepared tools와 Volatility 심볼 메타데이터

`--tools-root`를 사용하면 메타데이터 파일도 반드시 함께 지정해야 합니다. 예시를 복사한 뒤 실제로 시험한 값으로 바꿉니다.

```bash
cp config/offline-components.example.json /tmp/offline-components.json
# version, license/terms, source, supported_os, architectures, path를 실제 값으로 수정
scripts/build_offline_bundle.sh \
  --output /media/usb/forensickit-bundle \
  --tools-root /opt/prepared-forensic-tools \
  --components-metadata /tmp/offline-components.json
```

`components`의 각 항목은 `kind`, `name`, `version`, `license`, `supported_os`, `architectures`, `path`, `source`를 기술합니다. 예를 들어 Volatility 실행 환경은 `kind: tool`, 심볼 스냅샷은 `kind: symbols`로 분리합니다. `path`는 prepared root 안의 상대 경로여야 하며 모든 일반 파일이 정확히 선언된 구성 요소에 포함되어야 합니다. 심볼의 적용 OS·아키텍처·스냅샷 날짜 또는 릴리스와 출처를 실제 값으로 기록하십시오.

빌더는 symlink와 특수 파일, 설명되지 않은 일반 파일을 거부합니다. v2의 `manifests/component-manifest.json`에는 소스, wheel, Debian 패키지, 규칙/카탈로그, prepared 도구·심볼의 버전, 라이선스 메타데이터/참조, 지원 환경, 크기와 SHA-256이 기록됩니다. `NOASSERTION` 또는 누락 라이선스는 준비 상태 경고이며 임의의 라이선스로 보충되지 않습니다. 이 메타데이터는 법률적 라이선스 호환성 검토를 대신하지 않습니다.

### 3. USB에서 변경 여부 검증

시스템을 변경하지 않는 검증을 먼저 수행합니다.

```bash
/media/usb/forensickit-bundle/install_offline.sh \
  /media/usb/forensickit-bundle \
  --verify-only
forensickit doctor --bundle /media/usb/forensickit-bundle
```

설치기는 `manifests/SHA256SUMS`, wheel 잠금 파일, 안전한 상대 경로, 소스 commit/dirty 상태, 구성 요소 manifest, 소스와 prepared-tools tar의 항목 형식을 검사합니다. `doctor --bundle`도 번들 manifest를 독립적으로 점검합니다. 저장소 루트의 `SHA256SUMS`는 번들 내부 `wheels/`에 들어갈 정식 ForensicKit wheel의 **파일명과 해시**를 게시하는 릴리스 manifest이며, 저장소 루트에서 `sha256sum -c`를 실행하기 위한 로컬 파일 목록이 아닙니다. 릴리스 게이트가 이 값과 실제 번들 wheel을 비교합니다. 어느 검사든 실패하면 USB를 다시 복사하거나 온라인 준비 장비에서 번들을 재생성하십시오.

### 4. 네트워크 없이 설치

```bash
/media/usb/forensickit-bundle/install_offline.sh \
  /media/usb/forensickit-bundle \
  --link-bin
forensickit doctor
forensickit self-test
```

기본 설치 위치는 `/opt/forensickit`입니다. 다른 위치는 `--prefix DIR`, APT 설치 생략은 `--no-apt`를 사용합니다. 설치기는 wheel에 `pip --no-index`, 로컬 Debian 패키지에 `apt-get --no-download`를 사용하고, 임시 staging 위치에서 설치와 self-test를 완료한 뒤 활성화합니다. `--link-bin`은 `/usr/local/bin/forensickit` 링크를 만들기 때문에 root/sudo 권한이 필요합니다. 링크를 만들지 않았다면 `/opt/forensickit/venv/bin/forensickit`을 실행합니다.

### 5. 기존 설치 업그레이드

비어 있지 않은 설치 prefix는 기본적으로 거부됩니다. 검증된 새 번들로 교체할 때만 `--upgrade`를 명시합니다.

```bash
/media/usb/forensickit-bundle-vNext/install_offline.sh \
  /media/usb/forensickit-bundle-vNext \
  --prefix /opt/forensickit \
  --upgrade \
  --link-bin
```

업그레이드는 체크섬이 일치하는 단 하나의 ForensicKit wheel을 강제 재설치하고 새 경로에서 버전과 self-test를 확인합니다. 비어 있지 않은 임의의 디렉터리를 `--upgrade`로 지우지 않도록 설치 marker와 실제 가상 환경·패키지 메타데이터를 함께 검사합니다. 활성화가 실패하면 가능한 경우 이전 prefix를 복구합니다. dirty 개발 번들은 설치도 기본 거부하며, 시험 목적일 때만 `--allow-dirty`를 추가할 수 있습니다.

## CLI 사용법

`forensickit --help`가 현재 설치본의 최종 기준입니다. 인자 없는 `forensickit`은 TUI를 엽니다.

| 명령 | 설명 |
| --- | --- |
| `analyze FILE [FILE ...]` | 하나 이상의 파일/디렉터리를 새 사건에서 분석 |
| `triage FILE [FILE ...]` | 빠른 내장 점검만 실행 |
| `recommend FILE` | 실행 없이 정당화된 도구 추천과 이유 출력 |
| `run TOOL FILE` | 등록된 로컬 도구 하나를 증거에 실행 |
| `tools [--json]` | 등록 도구의 탐지/누락 상태 표시 |
| `doctor [--bundle DIR] [--json]` | Python, 필수 의존성, 사건 경로, 디스크, 도구, Volatility, 번들 준비 상태 점검 |
| `self-test [--json]` | 결정론적 설치 런타임 smoke test |
| `tui [CASE_DIR]` | 새 분석 화면 또는 기존/부분 사건 열기 |
| `artifacts/findings/flags/search-hits/errors CASE_DIR [--json]` | 사건 데이터베이스 항목 조회 |
| `report CASE_DIR` | JSON/Markdown/HTML, timeline/search CSV 보고서 재생성 |

### 분석 모드

- 기본 `analyze`와 `triage`: 내장 분석·검색·추출·재귀만 수행하고 외부 도구는 실행하지 않습니다.
- `--auto`: 분류와 관찰 근거가 강하고 설치된 도구를 실행합니다.
- `--deep`: 비용이 큰 carving, stego, 메모리/디스크 열거와 추출 계획까지 허용합니다.
- `--plan`: 계획만 만들며 외부 명령을 실행하지 않습니다.
- `--no-run`: 모드와 관계없이 외부 도구 실행을 막습니다. 예를 들어 `--auto --no-run`으로 자동 모드의 계획을 안전하게 미리 볼 수 있습니다.

### 자주 쓰는 옵션

| 분류 | 옵션 | 의미 |
| --- | --- | --- |
| 사건 | `--workspace DIR` | 사건 디렉터리를 만들 기준 경로. 기본값 `cases` |
| 출력 | `--json`, `--verbose` | 결과 JSON 출력 또는 계획 argv·도구 실행·오류 상세 출력 |
| 검색 | `--flag-prefix PREFIX`, `--exact-string TEXT`, `--search-term TEXT`, `--regex REGEX` | 반복 지정 가능한 사용자 검색 조건 |
| 검색 한도 | `--max-search-bytes N`, `--search-timeout SEC`, `--decode-depth N` | 파일당 검색 바이트, 파일당 시간, 반복 디코딩 깊이 조정 |
| 재귀/추출 | `--recursive`/`--no-recursive`, `--extract`/`--no-extract` | 자식 분석 또는 내장 추출 사용 여부. 둘 다 기본 활성화 |
| 도구 선택 | `--tool NAME`, `--category NAME` | 도구 이름 allowlist 또는 프로필/범주 필터. 반복 가능 |
| 실행 제한 | `--timeout SEC`, `--jobs N`, `--memory-jobs N` | 도구 시간 제한과 일반/메모리 동시 실행 수 |
| Linux 자원 제한 | `--tool-memory-bytes N`, `--tool-output-bytes N` | 도구 프로세스 주소 공간과 생성 파일 하나의 최대 크기 |
| 메모리 | `--pid PID` | 심층 메모리 추출 대상 PID. 반복 가능, 최대 16개 |

`--flag-pattern`도 하위 호환용 고급 플래그 정규식으로 남아 있지만 새 사용법에서는 `--flag-prefix` 또는 명시적인 `--regex`를 권장합니다. 각 하위 명령이 받는 옵션 범위는 다르므로 `forensickit COMMAND --help`로 확인하십시오. 예를 들어 `recommend`는 다중 파일이 아니라 파일 하나만 받습니다.

### 분석 예시

기본 `CTF{...}`, `FLAG{...}` 검색을 유지하면서 대회별 조건을 추가합니다.

```bash
forensickit analyze evidence/ --auto \
  --flag-prefix 'ACME' \
  --exact-string 'Account=Alice' \
  --search-term 'example.test' \
  --regex 'ticket-[0-9]{4}'
```

- `--flag-prefix ACME`와 `--flag-prefix 'ACME{'`는 모두 제한된 `ACME{...}` 후보 형식을 추가합니다.
- `--exact-string`은 대소문자를 구분합니다.
- `--search-term`은 파일명과 내용의 대소문자를 구분하지 않는 단서 검색입니다.
- `--regex`는 명시적 고급 모드입니다. lookaround, backreference, 중첩 반복, 반복되는 alternation 등 위험한 패턴은 거부하고 각 매치 작업에 timeout을 적용합니다.
- 디코딩된 결과는 원본 오프셋이라고 가장하지 않고 인코딩된 원본 범위와 변환 체인을 보존합니다.

여러 증거를 한 사건에 넣을 수 있습니다.

```bash
forensickit analyze disk.E01 notes.txt Manifest.db --auto
```

명시적으로 전달한 디렉터리는 제한된 immutable root 묶음으로 취급합니다. 내부 일반 파일을 결정론적 순서로 등록하며 symlink는 따라가지 않습니다. iOS 백업의 `Manifest.db`와 40자리 hex payload 파일도 이 방식으로 정확히 연결합니다.

```bash
forensickit analyze /evidence/ios-backup --auto
```

특정 도구만 직접 실행할 때는 카탈로그의 이름을 사용합니다.

```bash
forensickit tools
forensickit run exiftool suspicious.jpg --timeout 30
forensickit run sevenzip archive.bin
```

직접 `run`해도 먼저 새 사건을 만들고 증거를 보존한 뒤 도구 출력, 발견, 플래그/검색 결과와 생성물을 등록하고 보고서를 만듭니다.

## TUI 사용법

표준 설치에는 Textual이 포함되므로 다음 중 하나로 시작합니다.

```bash
forensickit
forensickit tui
forensickit tui cases/<case-directory>
```

새 분석에서는 증거 파일/디렉터리, 사건 기준 경로, Quick/Automatic/Deep/Plan 모드, 선택 검색 조건과 메모리 PID를 입력하고 **Analyze**를 누릅니다. 고급 정규식은 문자열을 입력한 뒤 **Enable regex**도 선택해야 합니다. 분석은 worker thread에서 실행되므로 결과 화면이 멈추지 않으며 진행 중인 사건도 부분적으로 열람할 수 있습니다.

| 키 | 기능 |
| --- | --- |
| `Ctrl+R` | 사건 내용 새로 고침 |
| `Ctrl+C` | 진행 중인 분석과 로컬 도구 취소 요청 |
| `c` | 선택한 플래그 후보 복사 |
| `F2` | 아티팩트 트리 탭 |
| `F3` | 분류/탐지 탭 |
| `F4` | 관찰 탭 |
| `F5` | 발견 요약 탭 |
| `q` | 진행 중이면 취소를 요청하고 종료 |

아티팩트, 분류, 관찰, 요약, 플래그, 메모리, Windows, 타임라인, 추출 파일, 실행 로그, 검색 결과, 다음 조치 탭을 제공합니다. 시작/종료 시간, PID, 사용자, 경로, 본문 필터와 표시 시간대 변환을 적용할 수 있습니다. 행을 선택하면 로컬 provenance를 제한된 길이로 미리 보고, 추출 파일은 명시적으로 지정한 디렉터리에 저장할 수 있습니다. **Retry**는 이전 사건을 덮지 않고 새 사건 폴더에서 전체 분석을 다시 시작합니다.

## 사건 폴더와 보고서

기본 `--workspace cases` 아래에 이름, UTC 시각, 사건 ID를 조합한 새 디렉터리가 매번 생깁니다.

```text
case/
├── evidence/        # 제출된 루트 증거의 SHA-256 이름 읽기 전용 사본
├── artifacts/       # 사건 내부 아티팩트 저장 영역
├── extracted/       # 부모·도구 실행과 연결된 제한적 추출물
├── outputs/         # 외부 도구 stdout
├── logs/            # 외부 도구 stderr 및 로그
├── cache/           # 격리된 임시/스냅샷 데이터
├── reports/
│   ├── report.json
│   ├── report.md
│   ├── report.html
│   ├── timeline.csv
│   └── search_results.csv
└── case.db
```

사람이 읽는 `report.md`와 `report.html`은 제목, 설명, 판정 및 권장 작업을 기본 한국어로 표시합니다. 도구명과 forensic 전문용어, 정확한 명령, 증거에서 가져온 문자열은 검증 가능성을 위해 원문을 유지하며, 자동화용 `report.json`의 schema key와 저장 값도 바꾸지 않습니다. `report.html`은 별도 프런트엔드 의존성이 없고 증거 문자열을 HTML escape합니다. `timeline.csv`는 artifact, EventRecordID 또는 원시 byte offset, 활동 클러스터 점수, parser observation, tool run, stdout provenance를 포함할 수 있습니다. 스프레드시트 수식처럼 보이는 증거 값은 CSV에서만 escape하고 JSON과 데이터베이스의 원본 값은 바꾸지 않습니다. `search_results.csv`는 보존된 플래그/검색 위치마다 한 행을 기록합니다.

완료되었거나 취소된 사건을 headless로 검토할 수 있습니다.

```bash
forensickit artifacts cases/<case-directory>
forensickit findings cases/<case-directory>
forensickit flags cases/<case-directory>
forensickit search-hits cases/<case-directory>
forensickit errors cases/<case-directory>
forensickit report cases/<case-directory>
```

자동 처리만 필요하면 조회 명령의 `--json` 또는 분석의 `--json`을 사용합니다. 보고서 파일이 지워졌거나 데이터베이스 내용으로 다시 만들고 싶으면 `forensickit report CASE_DIR`을 실행합니다.

## 안전한 대회 운영 워크플로

1. 대회와 동일한 OS 이미지·아키텍처의 준비 장비에서 외부 도구와 오프라인 번들을 만듭니다.
2. clean commit에서 번들을 생성하고 `--verify-only`, `doctor --bundle`, release gate가 각각 실제로 통과하는지 확인합니다.
3. USB를 실제 대회 장비에 복사한 뒤 네트워크를 끊고 설치, `doctor`, `self-test`, 대표 샘플 분석을 수행합니다.
4. 사건마다 충분한 여유 공간이 있는 별도 `--workspace`를 사용하고, 원본 매체는 가능하면 하드웨어/OS 수준에서도 읽기 전용으로 유지합니다.
5. 먼저 `triage` 또는 `--plan`, 다음 `--auto`, 필요할 때만 `--deep` 순서로 비용을 늘립니다.
6. `--verbose`에서 추천 이유와 정확한 argv를 확인하고, `[MISSING]`, `[ERROR]`, timeout을 보고서의 미검증 범위로 취급합니다.
7. 플래그 후보는 source, location, transform chain, parent chain을 따라 원본 문맥과 문제 형식을 확인한 후 제출합니다.
8. 사건 폴더 전체와 원본 해시를 함께 백업합니다. `outputs/` 한 파일만 떼어내면 재현 계보가 끊깁니다.

`Ctrl+C`는 첫 입력에서 정상 취소를 요청하고 실행 중인 프로세스 그룹을 중지하며 상태를 `canceled`로 기록합니다. 취소된 사건의 부분 결과와 로그도 남습니다.

## 기본 안전 한도

기본값은 일반적인 4 vCPU/16 GiB 대회 워크스테이션을 염두에 둔 보수적 값입니다.

| 항목 | 기본값 |
| --- | ---: |
| 재귀 깊이 | 4 |
| 사건당 아티팩트 수 | 1,000 |
| 누적 추출 바이트 | 2 GiB |
| 자식 아티팩트 하나의 크기 | 512 MiB |
| 도구 timeout 상한 | 180초 |
| 일반 도구 동시 실행 | 2 |
| 메모리 도구 동시 실행 | 1 |
| Linux 도구별 주소 공간 | 6 GiB |
| Linux 생성 파일 하나의 크기 | 2 GiB |
| 도구 실행 하나의 생성 파일/누적 크기 | 1,000개 / 2 GiB |
| 파일당 통합 검색 | 최대 2 GiB / 20초 |
| 검색 청크와 경계 overlap | 1 MiB / 기본 16 KiB |
| 최대 매치 길이 | 4,096자 |
| 디코딩 | 깊이 3, 영역 2,000개, 결과 64 MiB |

CLI로 조절 가능한 주 한도는 `--timeout`, `--jobs`, `--memory-jobs`, `--tool-memory-bytes`, `--tool-output-bytes`, `--max-search-bytes`, `--search-timeout`, `--decode-depth`입니다. 재귀 깊이·총 아티팩트 수 같은 나머지 값은 현재 공개 CLI 옵션이 아니며 코드의 `ForensicKitConfig`를 사용하는 통합 환경에서 설정합니다. 한도를 높일수록 신뢰도가 자동으로 높아지는 것이 아니라 분석 시간, 디스크 사용량, 악성 압축물 노출 면적이 함께 커집니다.

## 오류 해결

### `forensickit: command not found`

가상 환경을 활성화했는지 확인하거나 전체 경로를 사용합니다.

```bash
source .venv/bin/activate
python -m forensickit --version
/opt/forensickit/venv/bin/forensickit --version
```

### `doctor`에서 `[MISSING]`

Python, PyYAML, Textual, workspace는 필수입니다. 외부 포렌식 도구 대부분은 `RECOMMENDED` 또는 `OPTIONAL`이므로 누락되어도 내장 분석은 동작할 수 있습니다. `doctor`의 종료 코드 0은 필수 항목이 정상이라는 뜻이지 모든 선택 도구가 설치됐다는 뜻은 아닙니다. `forensickit tools --json`으로 정확한 실행 파일 탐지 결과를 확인하십시오.

### Volatility가 실패하거나 심볼을 찾지 못함

```bash
export FORENSIC_VOL_SYMBOLS=/opt/forensic-tools/volatility-symbols
forensickit doctor
```

`doctor`가 확인하는 후보는 `FORENSIC_VOL_SYMBOLS`, `/opt/forensic-tools/volatility-symbols`, 사용자 Volatility 캐시, 설치된 volatility3 패키지의 symbols 디렉터리입니다. 단순히 파일 수가 있다고 모든 이미지가 지원되는 것은 아닙니다. 이미지 OS/build에 맞는 심볼과 실제 사용할 Volatility 버전으로 대표 메모리 샘플을 시험하십시오. symbol missing, image/layer mismatch, 지원하지 않는 plugin/argument, 일반 plugin 실패는 사건에 서로 다른 오류로 남습니다.

### 정규식이 거부됨

무제한 정규식 실행을 막기 위한 정상 동작입니다. 복잡한 lookaround/backreference를 제거하고 가능한 경우 `--flag-prefix`, `--exact-string`, `--search-term`으로 바꾸십시오.

### 번들 생성이 dirty worktree 또는 기존 출력 때문에 실패함

릴리스 번들은 의도한 변경을 커밋한 뒤 새 출력 경로로 다시 만듭니다. `--allow-dirty`는 폐기 가능한 개발 검증에만 사용하십시오. 빌더가 기존 출력 디렉터리를 자동 삭제하지 않는 것은 검증된 준비물을 실수로 덮어쓰지 않기 위해서입니다.

### 오프라인 설치가 prefix 또는 체크섬 때문에 실패함

먼저 `--verify-only`로 변조/복사 오류를 확인합니다. 기존 설치를 의도적으로 교체할 때만 `--upgrade`를 사용하고, 다른 설치를 보존하려면 새 `--prefix`를 선택합니다. 배포판/버전/아키텍처 불일치 경고가 나오면 해당 장비와 일치하는 온라인 환경에서 번들을 다시 만드는 것이 안전합니다.

### 분석이 느리거나 디스크가 부족함

`triage` 또는 `--no-run`으로 범위를 줄이고 `--jobs`, 검색 바이트, 디코딩 깊이를 낮춥니다. 대형 메모리·디스크·carving 작업은 `--deep` 전에 여유 공간을 확인하십시오. `doctor`의 5 GiB 이상 권장은 최소 준비 신호일 뿐, 증거 크기의 여러 배가 필요한 추출 작업을 보장하지 않습니다.

### 일부 도구만 실패함

`forensickit errors CASE_DIR`, TUI 실행 로그, `logs/`와 `outputs/`를 확인합니다. timeout·비정상 종료·출력 한도·누락 도구는 전체 사건을 폐기하지 않습니다. 실패한 도구의 결론만 미검증으로 두고 보존된 argv와 로그로 수동 재현하십시오.

## 개발, 테스트, 릴리스 게이트

개발 환경을 준비하고 전체 테스트를 실행합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[test]'
python -m pytest
python -m compileall -q src tests
bash -n install_forensics.sh scripts/*.sh
forensickit self-test
```

최종 릴리스 후보는 clean commit에서 다음 게이트로 닫습니다.

```bash
scripts/release_gate.sh --bundle /media/usb/forensickit-bundle
```

게이트는 기본적으로 수정되거나 추적되지 않은 파일이 있는 작업 트리를 거부하고, `git diff --check`, 버전 일치, 로컬 compile/shell syntax 검사, 전체 pytest, 직접 synthetic test runner, 설치된 core self-test를 수행합니다. `--bundle`을 지정하면 번들의 commit·source archive·wheel checksum/lock, Doctor 번들 검사와 installer의 `--verify-only`도 확인합니다. 테스트 의존성이 설치된 오프라인 Python이 별도라면 `FORENSICKIT_PYTHON` 환경 변수로 지정할 수 있습니다. `--allow-dirty` 결과는 개발 중 증거일 뿐 릴리스 가능 판정이 아닙니다.

## 제한 사항과 실제 환경에서 반드시 검증할 항목

- 내장 파서는 결정론적 안전 한도 안의 triage와 제한적 추출을 목표로 합니다. 손상되거나 거대하거나 희귀한 파일시스템/프로토콜의 완전 열거·복구 도구를 대체하지 않습니다.
- UDF/ISO, FAT/exFAT/ext/NTFS, PCAP 프로토콜 재조립은 지원 구조와 경계가 명시적으로 제한됩니다. 중요한 결과는 7-Zip, Sleuth Kit, tshark 등 독립 도구와 교차 검증하십시오.
- EWF 등 외부 컨테이너, 암호화·압축된 트래픽/파일, 최신 또는 알려지지 않은 스키마는 준비된 외부 도구나 수동 분석이 필요할 수 있습니다.
- Windows 캐시, Prefetch, Amcache, Shimcache, 브라우저·Jump List 기록은 실행/사용의 단서이지 단독 확정 증거가 아닙니다. 원시 시간대와 epoch 의미를 보존한 상태에서 다른 아티팩트와 확인하십시오.
- 전체 시스템 메모리는 실제 OS/build와 일치하는 Volatility 심볼이 있어야 합니다. 최종 USB의 Volatility 버전, 플러그인 CLI, Windows/Linux 대표 이미지, 선택 PID dump를 대회 장비에서 직접 시험해야 합니다.
- `install_forensics.sh --full`은 저장소와 네트워크 상태에 따라 일부 선택 도구를 건너뛸 수 있습니다. 설치 목록이 아니라 `doctor`, `tools`, 실제 샘플 실행 결과를 준비 완료 기준으로 삼으십시오.
- 오프라인 APT 번들은 동일 Debian 계열 릴리스와 아키텍처에서만 준비·검증해야 합니다. VM에서 만든 번들이 현장 배포판에서 동작할 것이라고 가정하지 마십시오.
- Linux의 메모리/출력 rlimit, 프로세스 그룹 취소, 파일 권한, TUI clipboard는 실제 배포판·셸·터미널에서 동작을 확인해야 합니다.
- 구성 요소 manifest의 라이선스 필드는 출처와 적용 조건을 기록할 뿐 법률 검토가 아닙니다. 도구·규칙·심볼의 배포 권한을 대회 규정과 각 라이선스에 따라 별도로 확인하십시오.
- 실제 민감 증거가 아니라 승인된 CTF/로컬 포렌식 범위에서 사용하십시오. 실증 테스트에는 합성 또는 공개 샘플을 사용하고 사건 폴더 전체를 민감 데이터로 취급하십시오.

더 세밀한 형식별 경계는 [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md), 보안 원칙은 [SECURITY.md](SECURITY.md), 조사 모델과 구현 지침은 [AGENTS.md](AGENTS.md)를 참고하십시오.
