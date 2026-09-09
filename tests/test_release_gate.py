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
        "\"$BUNDLED_INSTALLER\" \"$BUNDLE\" --verify-only", "SOURCE_COMMIT",
        "SOURCE_DIRTY", "source archive does not exactly match git archive HEAD",
        "root SHA256SUMS", "scripts/wheelhouse_lock.py", "cmp -s",
    ):
        assert required in script


def test_wheelhouse_lock_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    import zipfile

    wheel_dir = tmp_path / "wheels"
    lock = tmp_path / "python-wheel-lock.json"
    wheel_dir.mkdir()
    wheel = wheel_dir / "forensickit-1.2.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "forensickit-1.2.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: ForensicKit\nVersion: 1.2.0\n"
            "Requires-Dist: PyYAML>=6.0\n",
        )

    write = subprocess.run(
        [
            str(ROOT / "scripts" / "wheelhouse_lock.py"),
            "--wheel-dir", str(wheel_dir), "--lock", str(lock), "--write",
        ],
        text=True, capture_output=True, check=False,
    )
    verify = subprocess.run(
        [
            str(ROOT / "scripts" / "wheelhouse_lock.py"),
            "--wheel-dir", str(wheel_dir), "--lock", str(lock),
        ],
        text=True, capture_output=True, check=False,
    )

    assert write.returncode == 0, write.stderr
    assert verify.returncode == 0, verify.stderr
    wheel.write_bytes(wheel.read_bytes() + b"tamper")
    rejected = subprocess.run(
        [
            str(ROOT / "scripts" / "wheelhouse_lock.py"),
            "--wheel-dir", str(wheel_dir), "--lock", str(lock),
        ],
        text=True, capture_output=True, check=False,
    )
    assert rejected.returncode == 1
    assert "does not exactly match" in rejected.stderr


def test_wheelhouse_lock_rejects_duplicate_distribution_candidates(tmp_path: Path) -> None:
    import zipfile

    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    for filename, version in (
        ("forensickit-1.2.0-py3-none-any.whl", "1.2.0"),
        ("forensic_kit-1.1.0-py3-none-any.whl", "1.1.0"),
    ):
        with zipfile.ZipFile(wheel_dir / filename, "w") as archive:
            archive.writestr(
                f"forensickit-{version}.dist-info/METADATA",
                f"Metadata-Version: 2.1\nName: ForensicKit\nVersion: {version}\n",
            )

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "wheelhouse_lock.py"),
            "--wheel-dir", str(wheel_dir),
            "--lock", str(tmp_path / "lock.json"), "--write",
        ],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 1
    assert "multiple candidates for distribution forensickit" in completed.stderr


def test_wheelhouse_lock_rejects_unexpected_directory(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    (wheel_dir / "nested-candidate").mkdir()

    completed = subprocess.run(
        [
            str(ROOT / "scripts" / "wheelhouse_lock.py"),
            "--wheel-dir", str(wheel_dir),
            "--lock", str(tmp_path / "lock.json"), "--write",
        ],
        text=True, capture_output=True, check=False,
    )

    assert completed.returncode == 1
    assert "symlink, directory, special entry, or non-wheel" in completed.stderr
