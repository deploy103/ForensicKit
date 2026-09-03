from __future__ import annotations

import base64
import gzip
from pathlib import Path

from forensickit.flags import FlagHunter
from forensickit.models import Artifact


def test_flag_hunter_follows_base64_gzip_chain(tmp_path: Path) -> None:
    evidence = tmp_path / "encoded.bin"
    evidence.write_bytes(base64.b64encode(gzip.compress(b"CTF{base64_gzip_chain}")))
    artifact = Artifact(
        id="artifact", case_id="case", path=str(evidence), logical_name="encoded.bin",
        sha256="x", size=evidence.stat().st_size,
    )

    candidates = FlagHunter([r"CTF\{[^}]+\}"]).scan(evidence, artifact)

    assert [(candidate.value, candidate.transform_chain) for candidate in candidates] == [
        ("CTF{base64_gzip_chain}", ["raw", "base64", "gzip"])
    ]


def test_flag_hunter_follows_gzip_base64_chain(tmp_path: Path) -> None:
    evidence = tmp_path / "compressed.bin"
    evidence.write_bytes(gzip.compress(base64.b64encode(b"CTF{gzip_base64_chain}")))
    artifact = Artifact(
        id="artifact", case_id="case", path=str(evidence), logical_name="compressed.bin",
        sha256="x", size=evidence.stat().st_size,
    )

    candidates = FlagHunter([r"CTF\{[^}]+\}"]).scan(evidence, artifact)

    assert [(candidate.value, candidate.transform_chain) for candidate in candidates] == [
        ("CTF{gzip_base64_chain}", ["raw", "gzip", "base64"])
    ]


def test_flag_hunter_follows_base32_chain(tmp_path: Path) -> None:
    evidence = tmp_path / "base32.bin"
    evidence.write_bytes(base64.b32encode(b"CTF{base32_chain}"))
    artifact = Artifact(
        id="artifact", case_id="case", path=str(evidence), logical_name="base32.bin",
        sha256="x", size=evidence.stat().st_size,
    )

    candidates = FlagHunter([r"CTF\{[^}]+\}"]).scan(evidence, artifact)

    assert [(candidate.value, candidate.transform_chain) for candidate in candidates] == [
        ("CTF{base32_chain}", ["raw", "base32"])
    ]
