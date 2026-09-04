# ForensicKit v1.1.0

v1.1.0은 ext4 활성 파일 복구 범위를 실제 extent tree까지 확장한 오프라인 포렌식 릴리스입니다.

## 주요 변경

- ext4 inode의 깊이 1 extent index와 leaf block을 제한된 범위에서 검증합니다.
- 루트와 활성 하위 디렉터리, 일반 파일이 같은 매퍼를 사용합니다.
- extent index 항목, leaf block/header/entry, 최종 데이터 블록의 정확한 바이트 위치를 관찰과 복구 finding에 보존합니다.
- 반복 leaf 포인터, 잘못된 논리 범위, tree/data block 겹침, sparse/uninitialized extent, 깊이 2 이상, 이미지 밖 매핑은 복구하지 않습니다.
- 복구된 파일은 기존 artifact graph와 Flag Hunter로 재귀 분석됩니다.

## 사용법

```bash
python3 -m pip install ./forensickit-1.1.0-py3-none-any.whl
forensickit doctor
forensickit analyze challenge.img --auto
```

## 검증 기준

- Python 3.12+
- 직접 synthetic regression: 283개
- 실행: `PYTHONPATH=src python3 scripts/run_direct_tests.py`
- 상세 안전 한도: `KNOWN_LIMITATIONS.md`

승인된 CTF 및 로컬 포렌식 분석에만 사용하세요. 원본 증거는 실행하거나 덮어쓰지 않으며, 탐지된 플래그는 출처와 함께 검토할 후보입니다.
