"""Everything a report page or a report download needs, in one place.

The web page, the PDF and the JSON file all come from the same report
dictionary (``report.build``) plus the action plan (``advice.plan``), so the
formats cannot tell different stories.
"""

import json
from typing import Any

from flask import Response

from tr02102_audit import advice, sarif
from tr02102_audit.web import pdf
from tr02102_audit.web.common import tr

# Report formats a user can choose before a check. English message ids.
FORMATS: dict[str, str] = {
    "web": "Web page",
    "pdf": "PDF document",
    "json": "JSON (machine-readable)",
    "sarif": "SARIF (for CI dashboards)",
}
DEFAULT_FORMAT = "web"


def context(rep: dict[str, Any]) -> dict[str, Any]:
    """Template variables for a report page."""
    actions = advice.plan(rep)
    return {
        "r": rep,
        "actions": actions,
        "summary": advice.summary(rep, actions),
        "profiles": {name: advice.configuration(name) for name in advice.PROFILE_TEXT},
        "profile_text": advice.PROFILE_TEXT,
        "priority_text": advice.PRIORITY_TEXT,
    }


def download(rep: dict[str, Any], fmt: str, stem: str) -> Response:
    """The report as a file in one of the download formats."""
    if fmt == "pdf":
        resp = Response(pdf.build(rep, tr), mimetype="application/pdf")
        resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.pdf"'
        return resp
    data = sarif.build(rep) if fmt == "sarif" else {**rep, "actions": advice.plan(rep)}
    resp = Response(json.dumps(data, indent=2), mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.{fmt}"'
    return resp
