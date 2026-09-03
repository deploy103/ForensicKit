# TOOL_CATALOG.md

이 문서는 ForensicKit이 설치/탐색/연동해야 할 포렌식 도구의 우선순위 카탈로그다.

`install_forensics.sh`와 `config/tool-catalog.yaml`도 같이 참고한다.

## P0 — 반드시 잘 지원

### Generic
- file/libmagic
- strings
- xxd/hexdump
- ExifTool
- YARA
- ripgrep
- 7z
- Binwalk 3
- legacy binwalk fallback

### Image / Stego
- pngcheck
- zsteg
- steghide
- stegseek
- outguess
- ImageMagick
- foremost
- scalpel
- bulk_extractor

### PCAP
- tshark
- capinfos
- tcpdump
- tcpflow
- Zeek when installed

### Disk / Filesystem
- SleuthKit: mmls, fsstat, fls, icat, tsk_recover
- ewf-tools
- xmount
- TestDisk
- PhotoRec

### Memory
- Volatility 3
- YARA

### PDF / Office
- pdfinfo
- pdftotext
- pdfimages
- pdfdetach
- qpdf
- pdfid.py
- pdf-parser.py
- oletools
- oledump.py

### Windows artifacts
- RegRipper
- Hayabusa
- Chainsaw
- Plaso/log2timeline if available
- libyal utilities where available

### Mobile
- sqlite3
- adb
- apktool
- JADX
- ALEAPP
- iLEAPP
- libimobiledevice tools

## P1 — 적극 지원

- ssdeep
- hashdeep
- magicrescue
- ext4magic
- extundelete
- libguestfs
- afflib
- reglookup
- hivex
- python-registry/regipy
- python-evtx
- rizin
- radare2
- Ghidra headless
- readelf
- objdump
- LIEF
- pefile
- capstone
- ffmpeg
- sox
- UBI Reader
- Jefferson
- UEFI firmware parser

## P2 — 있으면 활용

GUI:
- Autopsy
- Guymager
- ImHex
- Cutter
- Ghidra GUI
- Wireshark GUI
- SQLiteBrowser

Local evidence password recovery:
- John the Ripper
- Hashcat
- fcrackzip
- pdfcrack
- bkcrack

These must never become remote attack features.

## Integration Principle

각 Tool은 단순 실행 여부가 아니라 아래를 가져야 한다.

- availability
- version
- accepted artifact types
- safe default command
- deep command
- timeout
- cost
- parser
- output artifacts
- failure interpretation

가장 많이 쓰는 도구부터 parser 품질을 높인다.
