# Security Policy

## Scope

ForensicKit is for authorized CTF and local digital-forensics evidence only.

## Runtime guarantees

- Submitted evidence is copied, hashed, made read-only, and never executed.
- Runtime analysis does not call external APIs, LLMs, or network services.
- External tools receive argv arrays without shell interpolation and run with timeouts.
- Extraction is bounded by depth, count, individual size, and cumulative size.
- Missing or failed optional tools are recorded without aborting the case.

`install_forensics.sh` and the bundle builder are deliberate workstation-preparation utilities and may download packages when run online. The installed analysis runtime remains local-only.

For this private repository, report vulnerabilities with a private GitHub security advisory and a synthetic reproducer. Do not attach sensitive real-world evidence.
