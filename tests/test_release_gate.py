from __future__ import annotations

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_release_gate_help_and_required_checks_are_present() -> None:
    completed = subprocess.run(
        [str(ROOT / "scripts" / "release_gate.sh"), "--help"],
        text=True, capture_output=True, check=False,
    )
    script = (ROOT / "scripts" / "release_gate.sh").read_text(encoding="utf-8")

    assert completed.returncode == 0
    assert "--bundle DIR" in completed.stdout
    for required in (
        "status --porcelain", "git diff --check", "bash -n", "compileall",
        "-m pytest", "scripts/run_direct_tests.py", "-m forensickit self-test", "doctor --bundle",
        "install_offline.sh \"$BUNDLE\" --verify-only",
    ):
        assert required in script
