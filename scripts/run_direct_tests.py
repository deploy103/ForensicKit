#!/usr/bin/env python3
"""Run the synthetic test suite when an offline pytest wheel is unavailable.

This is deliberately narrow: it supports the repository's current ``tmp_path``
and ``case_artifact`` fixtures, performs no discovery outside ``tests/``, and
returns non-zero for an unsupported fixture rather than silently skipping it.
It is a competition-image fallback, not a replacement for the normal pytest
suite when pytest is installed.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib
import inspect
from io import StringIO
import sys
import tempfile
import traceback
import types
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    import_root_text = str(import_root)
    if import_root_text not in sys.path:
        sys.path.insert(0, import_root_text)


TEST_MODULES = (
    "tests.test_engine_pipeline",
    "tests.test_flags",
    "tests.test_pcap_reassembly",
    "tests.test_registry_planner",
    "tests.test_rules_profiles",
    "tests.test_triage",
    "tests.test_workspace_extraction",
    "tests.test_tools",
    "tests.test_release",
    "tests.test_udf",
    "tests.test_unified_search",
    "tests.test_windows_artifacts",
    "tests.test_browser",
    "tests.test_session",
    "tests.test_bundle_manifest",
    "tests.test_selftest",
    "tests.test_tui",
    "tests.test_release_gate",
    "tests.test_investigation_chain",
)


def _install_pytest_fixture_shim() -> None:
    """Permit importing test_tools without weakening its test assertions."""
    if "pytest" in sys.modules:
        return
    shim = types.ModuleType("pytest")

    def fixture(function=None, **_kwargs):
        if function is None:
            return lambda decorated: decorated
        return function

    shim.fixture = fixture  # type: ignore[attr-defined]

    @contextmanager
    def raises(exception_type, match=None):
        try:
            yield
        except exception_type as exc:
            if match is not None:
                import re
                if re.search(match, str(exc)) is None:
                    raise AssertionError(
                        f"exception text {str(exc)!r} does not match {match!r}"
                    ) from exc
        else:
            raise AssertionError(f"did not raise {exception_type.__name__}")

    shim.raises = raises  # type: ignore[attr-defined]
    sys.modules["pytest"] = shim


class _CaptureFixture:
    def __init__(self) -> None:
        self.stdout = StringIO()
        self.stderr = StringIO()

    def readouterr(self):
        captured = types.SimpleNamespace(
            out=self.stdout.getvalue(), err=self.stderr.getvalue(),
        )
        for stream in (self.stdout, self.stderr):
            stream.seek(0)
            stream.truncate(0)
        return captured


@contextmanager
def _captured_streams():
    fixture = _CaptureFixture()
    with redirect_stdout(fixture.stdout), redirect_stderr(fixture.stderr):
        yield fixture


def _fixture_values(module: types.ModuleType, function, tmp_path: Path) -> tuple[dict[str, object], list[object]]:
    values: dict[str, object] = {}
    cleanup: list[object] = []
    for parameter in inspect.signature(function).parameters:
        if parameter == "tmp_path":
            values[parameter] = tmp_path
            continue
        if parameter == "capsys":
            generated = _captured_streams()
            values[parameter] = generated.__enter__()
            cleanup.append(generated)
            continue
        if parameter == "case_artifact" and hasattr(module, "case_artifact"):
            generated = module.case_artifact(tmp_path)
            if inspect.isgenerator(generated):
                values[parameter] = next(generated)
                cleanup.append(generated)
            else:
                values[parameter] = generated
            continue
        raise RuntimeError(f"unsupported direct-test fixture: {parameter}")
    return values, cleanup


def run(modules: tuple[str, ...]) -> tuple[int, list[str]]:
    _install_pytest_fixture_shim()
    failures: list[str] = []
    passed = 0
    for module_name in modules:
        module = importlib.import_module(module_name)
        tests = [
            function for name, function in inspect.getmembers(module, inspect.isfunction)
            if name.startswith("test_") and function.__module__ == module_name
        ]
        for function in tests:
            with tempfile.TemporaryDirectory(prefix="forensickit-direct-test-") as raw_directory:
                cleanup: list[object] = []
                try:
                    values, cleanup = _fixture_values(module, function, Path(raw_directory))
                    function(**values)
                except BaseException:
                    failures.append(f"{module_name}.{function.__name__}\n{traceback.format_exc()}")
                else:
                    passed += 1
                finally:
                    for generated in reversed(cleanup):
                        if inspect.isgenerator(generated):
                            generated.close()
                        else:
                            generated.__exit__(None, None, None)
    return passed, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modules", nargs="*", help="dotted test module names; defaults to the full synthetic suite")
    arguments = parser.parse_args()
    passed, failures = run(tuple(arguments.modules) if arguments.modules else TEST_MODULES)
    print(f"direct synthetic tests: {passed} passed, {len(failures)} failed")
    for failure in failures:
        print(f"\n{failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
