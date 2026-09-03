# AGENTS.md

## Project

ForensicKit is an offline-first CTF digital-forensics orchestration platform.

The competition environment may have:
- no Internet access
- no AI/LLM access
- a supplied Ubuntu or Kali workstation
- strict time pressure
- permission to bring local forensic tools and scripts

The final runtime must therefore be deterministic, reproducible, local-only, and usable without any network dependency.

## Primary Objective

Given one or more local evidence artifacts, ForensicKit should:

1. Preserve the original evidence.
2. Hash and identify the artifact using signatures rather than extensions.
3. Perform fast generic triage.
4. Classify likely artifact/profile types.
5. Generate observations and hypotheses.
6. Select appropriate tools and tool options.
7. Optionally execute the selected tools.
8. Parse useful output instead of dumping raw stdout only.
9. Register extracted/generated child artifacts.
10. Recursively analyze useful child artifacts.
11. Search for configurable CTF flag candidates.
12. Show the exact evidence chain that produced each finding.
13. Produce machine-readable and human-readable reports.

The product is not a simple command wrapper. The important component is the decision engine that decides WHAT to run, WHEN to run it, and WHY.

## Investigation Model

Always model analysis as:

Evidence -> Observation -> Hypothesis -> Verification -> Finding

Every finding must retain:
- source artifact
- source tool/rule
- exact command if applicable
- output/log reference
- extraction/parent chain
- confidence or severity when meaningful

## Runtime Restrictions

The completed competition build MUST:
- work fully offline
- never call an external API
- never depend on an LLM
- never require Docker
- never execute submitted evidence as a program
- never open unsolicited network connections
- avoid modifying original evidence
- use timeouts for external commands
- bound recursion depth and extraction size
- record tool failures without crashing the full case
- remain usable when some external tools are missing

## Preferred Technology

Primary implementation language:
- Python 3.12+

Recommended libraries:
- Typer
- Textual
- Rich
- Pydantic v2
- SQLAlchemy
- SQLite
- PyYAML
- python-magic
- Jinja2
- yara-python
- construct
- LIEF
- pefile
- capstone
- Pillow
- pypdf
- oletools
- python-registry / regipy
- python-evtx
- scapy / dpkt
- networkx
- pytest

Use other dependencies when they materially improve forensic coverage or reliability.

Do not introduce Rust/Go/native services merely for architectural appearance. Native helper tools are fine when they provide real forensic value.

## Required Architecture

Keep these concerns separate and independently testable:

- Case / Workspace Manager
- Evidence Manager
- Artifact Model
- Artifact Identification Engine
- Observation Engine
- Classification Engine
- Rule Engine
- Profile Engine
- Tool Registry
- Tool Planner
- Task Scheduler
- Tool Runner
- Output Parser Framework
- Finding Engine
- Extraction Manager
- Recursive Analyzer
- Flag Hunter
- Artifact Graph
- Reporting
- CLI
- Textual TUI
- Doctor / Environment Validation

Avoid a giant application module.

## Data Model

At minimum model:

### Case
- id
- name
- created_at
- workspace
- configuration

### Artifact
- id
- case_id
- parent_id
- path
- logical_name
- sha256
- size
- mime
- magic
- artifact_type
- depth
- created_by_tool_run_id

### Observation
- artifact_id
- key/type
- value
- source
- confidence

### Finding
- artifact_id
- title
- category
- severity
- confidence
- explanation
- supporting evidence

### ToolRun
- artifact_id
- tool
- command argv
- start/end
- timeout
- exit code
- stdout path
- stderr path
- generated files

### FlagCandidate
- artifact_id
- value
- encoding/transform chain
- source
- offset/location when available
- confidence

## Workspace Layout

Use an isolated workspace, for example:

case/
  evidence/
  artifacts/
  extracted/
  outputs/
  logs/
  cache/
  reports/
    report.json
    report.md
  case.db

Original evidence must never be overwritten.

## Artifact Identification

Never trust the extension alone.

Use combinations of:
- magic bytes
- libmagic/file
- MIME
- file size
- known headers and trailers
- container signatures
- entropy
- strings
- metadata
- embedded signatures
- structural anomalies
- parser success/failure

An artifact may receive multiple classifications.

## Analysis Modes

### triage
Fast, safe, low-cost checks. Target: seconds, not minutes.

### auto
Run strongly justified tools based on classification and observations.

### deep
Allow expensive carving, exhaustive stego checks, broader parser passes, memory/disk enumeration, etc.

### plan / no-run
Show what would be executed and why without invoking external tools.

The planner must account for:
- confidence
- tool availability
- artifact size
- task cost
- expected value
- CPU/RAM budget
- dependency on prior findings

## Rule Engine

Rules should be declarative where practical.

Support YAML rule definitions for conditions such as:
- artifact type
- MIME
- magic
- header/footer conditions
- metadata
- strings
- entropy range
- embedded signature
- structural anomaly
- previous observation/finding
- previous tool result

A rule may emit:
- observations
- findings
- confidence changes
- recommended tools
- auto-mode tools
- deep-mode tools
- parser/extractor actions

Example behavior:
PNG + bytes after IEND + PK signature => possible appended ZIP => prioritize binwalk/7z/carving.

Do not make the entire engine dependent on YAML. Complex forensic parsers may use Python code, but rule configuration should remain easy to extend.

## Tool Registry

External tools must live in a central registry.

Each tool definition should include:
- canonical name
- executable candidates
- supported platforms
- supported artifact/profile types
- command templates as argv arrays
- modes/options
- timeout
- cost
- expected outputs
- output parser
- whether files are generated
- availability/version detection
- dependency hints

Never build shell commands by unsafely concatenating artifact paths.

Missing tools must be reported and skipped.

## Tool Profiles

Implement high-quality logic for at least:

1. Generic
2. Image
3. Steganography
4. Archive / container
5. PCAP / network capture
6. PDF
7. Office / OLE / OOXML
8. SQLite
9. Windows EVTX
10. Windows Registry
11. Disk image
12. Filesystem
13. Memory dump
14. Android/mobile
15. iOS/mobile backup
16. Executable
17. Firmware
18. Audio/video
19. Unknown binary

Highest priority:
- Generic
- Image/Stego
- Archive
- PCAP
- Memory
- Disk/Filesystem
- Windows artifacts
- Mobile

## Recursive Analysis

When tools extract or carve files:
- register them as child artifacts
- hash them
- deduplicate by SHA256
- re-enter the analysis pipeline when justified

Protect against:
- infinite recursion
- archive bombs
- duplicate extraction
- pathological file counts
- excessive disk usage
- recursive container loops

Configuration must expose:
- max depth
- max extracted bytes
- max artifact count
- per-tool timeout
- global job count

## Flag Hunter

Default common patterns should include:
- CTF{...}
- FLAG{...}

Allow custom patterns:
- --flag-pattern
- config file patterns

Inspect:
- ASCII
- UTF-8
- UTF-16 LE/BE
- common printable string regions

Perform evidence-driven lightweight transforms such as:
- Base64
- hex
- URL decode
- ROT13
- gzip/zlib
- common compression wrappers

Only attempt simple XOR decoding when there is a bounded blob or evidence such as a known flag prefix. Do not perform unbounded brute force.

For every candidate preserve:
- original artifact
- source region/string
- transform chain
- final candidate
- offset/location when known

## Artifact Graph

Maintain lineage:

original.png
  -> binwalk
     -> hidden.zip
        -> unzip
           -> flag.txt

A finding must be traceable back to the original evidence.

Use this graph in the report and TUI.

## CLI

Required commands:

forensickit
forensickit analyze FILE
forensickit triage FILE
forensickit recommend FILE
forensickit run TOOL FILE
forensickit tools
forensickit doctor
forensickit artifacts
forensickit findings
forensickit flags
forensickit report WORKSPACE

Important options:

--auto
--deep
--plan
--no-run
--recursive / --no-recursive
--extract
--category
--tool
--timeout
--jobs
--workspace
--flag-pattern
--json
--verbose

## TUI

`forensickit` with no subcommand should launch a Textual TUI.

The TUI should show:
- current case/evidence
- artifact tree
- detection/classification
- observations
- findings
- recommended tools
- running tasks
- completed tool runs
- selected raw output
- flag candidates

Keyboard-first operation is required.

Do not make the TUI mandatory for headless use.

## Output Parsing

Do not only display raw tool stdout.

Create parsers for important tools and normalize useful results.

Raw stdout/stderr must still be saved under logs/outputs for reproducibility.

At minimum prioritize parsing:
- file/libmagic
- exiftool
- binwalk/binwalk3
- pngcheck
- zsteg
- 7z
- tshark/capinfos
- SleuthKit basics
- Volatility 3
- pdfid/pdf-parser
- oletools/oledump
- Hayabusa/Chainsaw
- RegRipper
- ALEAPP/iLEAPP

## Doctor

`forensickit doctor` is a first-class competition feature.

Check:
- Python version
- Python dependencies
- external executables
- versions
- rule packs
- Volatility symbols/cache
- writable workspace
- free disk space
- important optional tools
- offline readiness

Clearly classify:
- REQUIRED
- RECOMMENDED
- OPTIONAL

Doctor must exit non-zero only when required components are broken.

## Reporting

Generate:
- report.json
- report.md

Optional:
- report.html

Reports must contain:
- case metadata
- evidence hashes
- detected types
- observations
- hypotheses/findings
- tools executed
- exact argv/commands
- exit codes
- important parsed results
- raw output locations
- extracted artifacts and hashes
- artifact lineage
- flag candidates
- errors
- recommended next steps

When a flag candidate is found, show it prominently but do not silently declare it definitive if evidence is weak.

## Security / Safety

This project is for authorized CTF/local forensic analysis only.

Do not implement:
- remote scanning
- brute forcing remote services
- persistence
- phishing
- credential theft from third-party systems
- C2
- data exfiltration

Local cracking/decoding of user-supplied CTF artifacts is acceptable.

## Testing

Use:
- unit tests
- integration tests
- end-to-end synthetic fixtures
- CLI smoke tests
- doctor tests
- missing-tool tests

Important synthetic chains:

PNG -> appended ZIP -> Base64 flag

PCAP -> HTTP object -> archive -> text -> flag

OOXML -> embedded object -> encoded flag

Memory fixture or mocked Volatility output -> process/file finding

Recursive archive -> deduplication and depth limits

Corrupted file -> graceful parser failure

## Development Style

Prefer:
- typed Python
- small modules
- dataclasses/Pydantic models
- explicit interfaces
- deterministic behavior
- readable logs
- dependency injection where useful
- easy extension of profiles/tools/rules

Avoid:
- unnecessary web servers
- cloud components
- Docker dependency
- distributed systems
- opaque metaprogramming
- over-engineered microservices

## Repository Integration

The repository includes `install_forensics.sh`.

Treat it as the initial workstation bootstrap, not immutable code.

Review it, improve it, and make `forensickit doctor` compatible with the tools it installs.

If a useful forensic utility is missing, add it when installation is reliable and legal for the target environment.

## README Requirement

README.md must be written for competition use.

A user should understand within 30 seconds:

1. how to check the machine
2. how to analyze a file
3. how to run auto mode
4. how to escalate to deep mode
5. where flags/findings appear
6. where raw evidence/results are stored

## Definition of Done

The project is not done until:

- offline runtime works
- CLI works
- TUI works
- doctor works
- common artifact classes work
- automatic tool selection works
- missing tools are tolerated
- recursive analysis works
- lineage works
- flag detection works
- reports work
- tests pass
- README is complete
- sample fixtures demonstrate real multi-stage analysis

## Continuous Work Rule

Do not end a turn after completing only one incremental task.

After each implementation:
1. test it,
2. record meaningful progress,
3. inspect remaining work,
4. immediately continue with the next task.

Do not use progress reports such as "work will continue" as a final response.

Only stop when:
- all currently actionable work is complete,
- a genuine user-dependent blocker exists,
- or execution is forcibly interrupted.
