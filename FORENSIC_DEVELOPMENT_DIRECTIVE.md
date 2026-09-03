# ForensicKit 지속 개발 지침

## 1. 프로젝트 정의

이 프로젝트는 몇 가지 포맷을 식별하는 소형 triage 도구가 아니다. 인터넷과 AI 사용이 제한된 CTF 현장에서 증거 수집, 구조 분석, 복구, 외부 도구 실행, 결과 상관분석, Flag 탐색, 보고서 생성을 하나의 흐름으로 처리하는 대규모 오프라인 디지털 포렌식 플랫폼이다.

현재 구현된 기능 목록은 완료 기준이 아니라 초기 기반이다. 지원 포맷의 개수만 늘리지 말고, 실제 증거 추출·삭제 흔적 복구·상관관계 분석·provenance 보존 능력을 깊게 구현한다.

## 2. 최상위 작업 원칙

1. 사용자가 지정한 종료 시각 전에는 프로젝트 완료를 선언하거나 작업을 자발적으로 종료하지 않는다.
2. 한 기능을 구현한 뒤 사용자 응답을 기다리지 말고 다음 우선순위 작업을 즉시 시작한다.
3. 계획, 검토, 문서 작성만으로 작업 단위를 끝내지 않는다. 각 작업 단위에는 실질적인 코드 변경이 포함되어야 한다.
4. placeholder, 빈 함수, TODO만 추가한 기능, 고정 출력 parser는 구현으로 인정하지 않는다.
5. 기존 기능과 사용자 변경 사항을 보존한다. 관련 없는 파일을 수정하거나 위험한 reset·강제 checkout·대량 삭제를 하지 않는다.
6. 외부 도구가 없으면 내부 parser, 선택적 adapter, 설치 manifest, synthetic fixture 중 가능한 방법으로 계속 진행한다.
7. 질문이 없어도 저장소, 기존 로그, capability를 근거로 다음 작업을 스스로 선택한다.
8. 설계 전체를 반복해서 다시 짜지 않는다. 기존 구조를 활용하되 구조적 문제가 실제 구현을 막을 때만 점진적으로 개선한다.
9. Docker를 필수 전제로 만들지 않는다. Ubuntu/Kali 및 4 CPU·16 GB 환경에서 오프라인 실행 가능해야 한다.
10. CTF 증거 파일은 신뢰할 수 없는 입력으로 취급한다. 추출 크기, 파일 개수, 재귀 깊이, 시간, 메모리 사용량을 제한한다.

## 3. 지속 작업 루프

저장소에 기존 동등 파일이 없다면 다음 상태 파일을 만든다.

- `WORK_QUEUE.md`: 대기·진행·완료 작업과 우선순위
- `WORK_LOG.md`: 시간, 변경 파일, 구현 내용, 검증 결과, 실패 원인, 다음 작업
- `CAPABILITY_MATRIX.md`: 포맷별 식별·파싱·추출·복구·외부 도구·검증 수준
- `KNOWN_LIMITATIONS.md`: 실제 제한과 미지원 구조

각 작업 단위에서 다음을 반복한다.

1. KST 현재 시각과 지정된 종료 시각을 확인한다.
2. 현재 코드와 상태 파일을 검사한다.
3. 가장 가치가 높은 미완성 기능 하나를 선택한다.
4. 실제 코드를 구현한다.
5. compile, smoke test, 최소 regression을 수행한다.
6. 새로 생성한 파일과 결과를 artifact graph/provenance에 연결한다.
7. 상태 파일을 갱신한다.
8. 종료 시각 전이면 다음 기능으로 즉시 넘어간다.

중간 보고는 `구현 내용 / 변경 파일 / 검증 결과 / 다음 작업`만 짧게 작성하고 보고 뒤에 멈추지 않는다.

## 4. 구현 우선순위

다음 순서로 작업을 선택한다.

1. 기존 코드에 자연스럽게 연결되며 실전 분석 능력이 크게 증가하는 기능
2. CTF 빈도가 높은 Windows, PCAP, 이미지, archive, memory 기능
3. 현재 식별만 가능하고 내부 증거 추출이 불가능한 포맷
4. 추출 결과를 자동으로 재귀 분석할 수 있는 기능
5. 외부 도구 raw output을 정규화된 finding으로 바꾸는 기능
6. timeline과 artifact 간 상관관계
7. 설치·오프라인 준비·doctor 개선
8. TUI와 보고서 편의 기능

## 5. 핵심 개발 백로그

### Windows와 파일시스템

- NTFS `$MFT` fixup, attribute, resident/non-resident data, data run, ADS
- STANDARD_INFORMATION/FILE_NAME 시간 비교와 timestomping 후보
- 삭제 FILE record, orphan record, `$I30`, `$UsnJrnl:$J`, `$LogFile`
- Recycle Bin `$I`/`$R`, LNK, Prefetch, Jump Lists 심화 분석
- FAT/exFAT deleted entry와 LFN, ext inode/extent/directory entry
- Amcache, Shimcache, UserAssist, BAM/DAM, MUICache, RecentDocs, TypedPaths
- ShellBags, Scheduled Tasks, Services, SRUM, Defender, PowerShell 흔적
- RDP, USB, 네트워크 프로필, 로그인 흔적과 timeline 상관분석
- Registry transaction log 및 dirty hive 복구 지원

### EVTX

- record/XML 추출과 주요 Event ID 정규화
- 로그인, 계정 변경, 프로세스 생성, 서비스 설치, 예약 작업, PowerShell, RDP, 로그 삭제, Defender 사건 분류
- 사용자·PID·IP·프로세스 경로·파일을 다른 artifact와 연결
- 시간순 사건 묶음과 의심 행위 scoring

### 메모리

- Volatility windows.info, pslist/psscan/pstree, cmdline, netscan 결과 정규화
- dlllist, handles, filescan, dumpfiles, malfind, vadinfo, modules, svcscan, yarascan
- list/scan 결과 차이를 이용한 은닉 후보 탐지
- process-network-file-command graph와 의심 프로세스 scoring
- dump된 파일을 새 artifact로 등록하고 자동 재귀 분석
- minidump stream 파싱 범위와 메모리 영역 추출 확대

### 네트워크

- retransmission과 out-of-order를 고려한 TCP stream 재조립
- HTTP request/response pair, chunked, multipart, gzip/deflate, object 복구
- DNS TXT/base32/hex 조각 재조립과 tunneling 후보
- FTP, SMTP, POP3, IMAP, SMB 파일 전송 흔적
- ICMP payload, ARP/DHCP 이상, TLS SNI/ALPN/certificate metadata
- stream별 Flag 탐색과 packet/stream offset provenance

### 이미지와 스테가노

- PNG ancillary chunk, IDAT/filter, CRC, 손상 크기, trailing data
- JPEG APP/COM/EXIF/XMP/ICC와 EOI 이후 overlay
- GIF frame/extension, palette/alpha 이상, RGB/RGBA bit-plane
- 제한된 LSB channel/order 탐색과 결과 scoring
- 이미지 내부 archive/document/executable carving
- zsteg, steghide, exiftool, pngcheck, QR/barcode 도구 결과 정규화

### 문서와 PDF

- OOXML relationship, external link, embedded object, VBA 추출
- VBA 문자열 결합·Chr 수준의 기본 난독화 해제
- OLE stream tree, RTF embedded object
- PDF xref table/stream, object stream, incremental update
- JavaScript, OpenAction, Launch, URI, attachment, 손상 객체 복구
- oletools, pdfid, pdf-parser, mutool 결과 정규화

### Archive와 carving

- 7z, RAR, CPIO, CAB, ISO 및 split archive 식별
- 중첩 archive 재귀 분석과 bomb/path traversal 방어
- 암호화 archive 식별 및 사용자가 제공한 제한된 후보 처리
- signature 기반 bounded carving과 false positive 억제
- carved artifact에 parent, offset, length, extraction method 저장
- 손상 archive에서 가능한 entry 목록과 부분 복구

### Mobile

- Android packages.xml, shared preferences, SMS/MMS, 통화, 연락처
- Android 브라우저, Wi-Fi, logcat, APK certificate/permission/component
- Android SQLite WAL/SHM, backup payload, boot/vendor_boot/ramdisk
- iOS Manifest.db domain/path mapping과 payload 자동 연결
- iOS SMS, 통화, Safari, 연락처, 메모, plist/bplist, 앱 container
- Cocoa/Unix/WebKit 등 timestamp 자동 판별과 정규화

### Firmware

- SquashFS, CPIO/initramfs, UBI/UBIFS, cramfs, device tree
- Android boot image와 kernel/rootfs 분리
- firmware 내부 filesystem 재귀 분석
- 설정, 계정 흔적, 인증서, 시작 스크립트 탐지
- binwalk, unsquashfs, jefferson, ubireader 결과 정규화

### SQLite와 브라우저

- schema/table 자동 요약, freelist/unallocated, WAL frame
- 삭제 record 후보와 confidence
- Chrome/Chromium History, Cookies, Downloads, visits, searches, extensions
- Firefox places.sqlite 및 다운로드 흔적
- 브라우저 timestamp 정규화와 URL-domain-file 상관관계
- 민감 필드 redaction 옵션

### Flag Hunter

- 사용자 지정 Flag 정규식과 format profile
- UTF-16 LE/BE, escaped hex, reversed string, JWT, binary, Morse 후보
- 제한된 single-byte/repeating XOR와 Caesar/ROT scoring
- 인코딩·압축 복합 체인의 깊이와 출력 크기 제한
- entropy, printable ratio, known prefix 기반 confidence
- 동일 Flag dedupe와 전체 변환 provenance

### Planner와 실행 엔진

- finding 기반 후속 도구 자동 계획과 dependency graph
- 실패 fallback, artifact hash cache, resume, 중복 실행 방지
- CPU/RAM/disk budget, 전역·도구별 timeout, 우선순위
- 새 artifact 생성 시 재귀 계획, 순환·무한 재귀 방지
- interruption 이후 case 재개와 결정적 결과 순서
- tool run 재시도 정책과 raw output 보존

### Timeline과 상관분석

- FILETIME, Unix, Cocoa, Chrome, FAT timestamp 보존·정규화
- 원본 timezone, 변환된 UTC, confidence를 함께 저장
- process/file/network/user/event 관계 분석
- 다운로드→실행→지속성, USB→복사→실행 같은 사건 흐름 탐지
- JSON/CSV/Markdown timeline과 근거 artifact 역추적

### 설치와 오프라인 운용

- Ubuntu/Kali 카테고리별 설치 스크립트
- 필수·권장·선택 도구와 apt/pipx/venv/binary 구분
- 버전, 라이선스, 설치 출처, hash manifest
- 오프라인 download manifest/bundle 준비 기능
- 일부 설치 실패가 전체 설치를 중단하지 않도록 구현
- Volatility3, SleuthKit, libewf, yara, binwalk, exiftool, oletools, tshark, bulk_extractor 연계
- doctor에서 설치 여부가 아닌 실제 실행 가능 여부 확인

### TUI와 보고서

- artifact tree, finding filter, tool run 상태, raw output 검색
- provenance 이동, Flag 후보 검토, 실행 취소, case 재개
- timeline 화면과 JSON/Markdown/CSV 내보내기
- 실패 원인, 재현 명령, tool argv, hash, offset 표시

## 6. 검증 원칙

기능 구현 속도를 유지하면서 각 작업 단위마다 가능한 범위에서 다음을 실행한다.

- `python -m compileall`
- 기존 직접 regression
- 최소 synthetic fixture
- CLI smoke test
- artifact와 provenance 생성 확인
- 동일 case 재실행 시 중복 등록 여부 확인

pytest가 없다는 이유로 멈추지 않는다. 오늘의 주목적은 기능 구현이며, 광범위한 fixture와 전체 E2E 테스트는 별도 작업 시점에 보강할 수 있다.

## 7. 작업 중단 조건

지정 시각 전에는 다음 경우에만 멈출 수 있다.

- 사용자 선택 없이는 데이터 손실 가능성이 있는 작업
- 필요한 권한이나 인증이 없어 진행할 수 없는 작업
- 저장소 손상 또는 환경 장애로 안전한 구현이 불가능한 경우

한 기능의 실패, 외부 도구 부재, 테스트 framework 부재, 어려운 parser 구현은 전체 작업 중단 사유가 아니다. 실패 원인을 기록하고 다음 구현 가능한 작업으로 이동한다.

## 8. 지정 시각 도달 시

현재의 안전한 작업 단위를 마무리한 뒤 다음만 수행한다.

1. compileall과 실행 가능한 핵심 regression
2. 상태 파일 갱신
3. 구현·검증·실패 내용을 구분한 짧은 보고
4. 다음 세션에서 이어갈 최우선 작업 10개 기록

이때도 프로젝트 전체 완료라고 표현하지 않고, 해당 작업 시간만 종료되었다고 표현한다.
