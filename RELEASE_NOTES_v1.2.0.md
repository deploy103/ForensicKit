# ForensicKit v1.2.0

v1.2.0 is the competition-readiness release of the deterministic, fully local
forensics workflow. It expands native disk, filesystem, archive, PCAP, Windows,
memory-orchestration, mobile, and unified-search coverage while retaining exact
artifact lineage and bounded execution.

## Competition workflow

```bash
python3 -m pip install ./forensickit-1.2.0-py3-none-any.whl
forensickit doctor
forensickit self-test
forensickit analyze challenge.bin --auto
```

Use `--deep` only when the time/resource budget allows expensive local tools.
Every discovered flag remains a candidate with source location and transform
provenance; it is not silently declared the answer.

## Release highlights

- Bounded recursive native extraction across common archives and filesystems,
  including complete Type-1 UDF Allocation Extent Descriptor chains.
- Unified flag/exact/keyword/advanced-regex search over evidence, children,
  parsed records, and tool output with grouped multi-location provenance.
- Windows Registry, Jump List, browser, EVTX, NTFS, memory-tool correlation,
  timeline, and offline Volatility planning improvements.
- Explicit Evidence → Observation → Hypothesis → Verification → Finding records.
- Keyboard-first active TUI with artifact tree, classifications, observations,
  findings, flags, timeline, tool runs, cancellation, and safe extraction save.
- Auditable offline bundle v2 with exact source provenance, component hashes,
  staged/rollback-safe installation, and an installed-runtime self-test.

## Final validation

Run `scripts/release_gate.sh --bundle BUNDLE` on the clean release commit. It
performs local compile and shell checks, the complete pytest suite, the core
self-test, Doctor bundle validation, and installer verification without network
access. A real full-system memory image still requires the matching staged
Volatility symbols, and the final USB bundle should be exercised on the exact
Ubuntu/Kali competition image before the event.

Authorized CTF and local forensic analysis only. Submitted evidence is copied,
hashed, never executed, and never overwritten.
