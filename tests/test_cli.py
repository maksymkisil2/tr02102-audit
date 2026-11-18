"""Tests for the command-line skeleton and the exit-code contract."""

import runpy
import sys
from importlib import resources
from pathlib import Path

import pytest

from tr02102_audit import __version__
from tr02102_audit.cli import main
from tr02102_audit.exit_codes import ExitCode


def test_exit_codes_are_a_stable_contract() -> None:
    # CI pipelines branch on these numbers; changing them is a breaking change.
    assert (ExitCode.OK, ExitCode.FINDINGS, ExitCode.ERROR) == (0, 1, 2)


def test_version_flag_prints_version_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == ExitCode.OK
    assert capsys.readouterr().out.strip() == f"tr02102-audit {__version__}"


def test_run_without_command_is_never_reported_as_success(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Nothing was audited, so a calling pipeline must not see exit code 0.
    assert main([]) == ExitCode.ERROR
    assert "usage: tr02102-audit" in capsys.readouterr().err


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--no-such-option"])

    assert excinfo.value.code == ExitCode.ERROR
    assert "unrecognized arguments" in capsys.readouterr().err


def test_help_states_authorised_use_only(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])

    assert "authorised use only" in capsys.readouterr().out.lower()


def test_package_is_runnable_as_module(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["tr02102-audit", "--version"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("tr02102_audit", run_name="__main__")

    assert excinfo.value.code == ExitCode.OK
    assert __version__ in capsys.readouterr().out


def test_stored_scan_as_pdf(tmp_path: Path) -> None:
    source = resources.files("tr02102_audit.web").joinpath("demo", "tls-typical.json")
    stored = tmp_path / "scan.json"
    stored.write_text(source.read_text("utf-8"), encoding="utf-8")
    out = tmp_path / "report.pdf"
    code = main(["evaluate", str(stored), "--format", "pdf", "--output", str(out)])
    assert code in (0, 1)
    assert out.read_bytes().startswith(b"%PDF")
    assert main(["evaluate", str(stored), "--format", "pdf"]) == 2, "pdf needs --output"
