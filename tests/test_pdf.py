"""The PDF report."""

import copy
import json
from importlib import resources
from typing import Any

import pytest

from tr02102_audit import report
from tr02102_audit.standards import defaults, load_builtin
from tr02102_audit.web import pdf

STANDARDS = defaults(load_builtin())


def observation(name: str) -> dict[str, Any]:
    text = resources.files("tr02102_audit.web").joinpath("demo", f"{name}.json").read_text()
    data: dict[str, Any] = json.loads(text)
    return data


@pytest.mark.parametrize("name", ["tls-weak", "tls-typical", "tls-good"])
def test_pdf_for_every_lab_server(name: str) -> None:
    data = pdf.build(report.build(observation(name), STANDARDS))
    assert data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")
    assert data.count(b"/Type /Page") >= 2, "summary, plan and evidence take several pages"
    assert b"DejaVuSans" in data, "the bundled font is embedded"


def test_translated_pdf() -> None:
    seen = []

    def tr(text: str, **params: object) -> str:
        seen.append(text)
        return ("Ü " + text) % params if params else "Ü " + text

    assert pdf.build(report.build(observation("tls-typical"), STANDARDS), tr).startswith(b"%PDF")
    assert "TLS audit report" in seen and "What to do, in this order" in seen
    assert "Standards met" in seen and "Required by:" in seen


def test_hostile_server_fields_cannot_inject_markup() -> None:
    obs = copy.deepcopy(observation("tls-typical"))
    hostile = '<font color="red">x</font><img src="/etc/passwd"/>&amp'
    obs["target"]["host"] = "example.org"
    obs["facts"]["certificate"]["subject_cn"] = hostile
    obs["facts"]["certificate"]["issuer_cn"] = "<para><b>"
    data = pdf.build(report.build(obs, STANDARDS))
    assert data.startswith(b"%PDF")
