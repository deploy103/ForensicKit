# ForensicKit v1.0.0

오프라인 CTF 디지털 포렌식 분석을 위한 첫 안정 버전입니다.

## 무엇을 하나요?

- 증거를 보존하고 SHA-256과 구조적 시그니처로 식별합니다.
- 관찰과 분류를 바탕으로 실행할 로컬 도구와 이유를 결정합니다.
- 추출된 파일을 제한된 범위에서 재귀 분석하고 원본까지 계보를 연결합니다.
- `CTF{...}`, `FLAG{...}`와 사용자 패턴을 변환 출처와 함께 탐색합니다.
- SQLite, `report.json`, `report.md`, `timeline.csv`로 재현 가능한 결과를 남깁니다.
- 외부 API, LLM, Docker 없이 완전히 오프라인으로 동작합니다.

## 가장 쉬운 사용법

```bash
python3 -m pip install .
forensickit doctor
forensickit analyze challenge.bin --auto
```

플래그는 `[FLAG]`, 상세 결과는 출력된 사건 폴더의 `reports/report.md`에서 확인합니다.

## 검증 기준

- Python 3.12+
- 직접 회귀 테스트: 282개
- 실행: `PYTHONPATH=src python3 scripts/run_direct_tests.py`
- 현재 한계: `KNOWN_LIMITATIONS.md`

승인된 CTF 및 로컬 포렌식 분석에만 사용하세요. 플래그 후보는 검토할 증거이며 자동 정답 선언이 아닙니다.
