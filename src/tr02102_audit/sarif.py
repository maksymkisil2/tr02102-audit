"""SARIF 2.1.0 output.

SARIF is the format CI dashboards read, GitHub code scanning among them. It
lets a TLS audit appear next to code findings and turns a scheduled scan into
an alert that is opened and closed automatically.

Mapping decisions, all of them deliberate:

* One SARIF rule per (standard, rule). Standards disagree, so the same control
  can be an error under one standard and a warning under another; prefixing the
  rule id with the standard id keeps both visible and unambiguous.
* ``fail`` becomes ``error``, ``warn`` becomes ``warning``, and ``inconclusive``
  becomes ``note``. Passing and not-applicable checks produce no result.
* ``inconclusive`` is reported rather than dropped, because a check that could
  not be completed must never look like a pass (principle P5).
* The location of a finding is the audited endpoint, not a file. It is given as
  an absolute ``tls://host:port`` URI plus a logical location, since there is no
  source line to point at.
"""

import hashlib
from datetime import UTC, datetime
from typing import Any

from tr02102_audit import __version__

SARIF_VERSION = "2.1.0"
SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/maksymkisil2/tr02102-audit"

# SARIF levels for our statuses. Statuses not listed produce no result.
LEVELS: dict[str, str] = {"fail": "error", "warn": "warning", "inconclusive": "note"}

# GitHub code scanning reads this property to sort and filter alerts (0.0-10.0).
SECURITY_SEVERITY: dict[str, str] = {
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}

# The level a rule reports when it is violated, derived from its severity.
DEFAULT_LEVEL: dict[str, str] = {
    "high": "error",
    "medium": "error",
    "low": "warning",
    "info": "note",
}


def _sarif_time(value: str) -> str:
    """Convert an ISO timestamp to the ``yyyy-MM-ddTHH:mm:ss.sssZ`` form SARIF wants."""
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        moment = datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return (
        moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    )


def _endpoint(target: dict[str, Any]) -> str:
    return f"{target.get('host', 'unknown')}:{target.get('port', 0)}"


def _fingerprint(standard_id: str, rule_id: str, endpoint: str) -> str:
    """Stable identity of a finding, so a dashboard can track it across runs."""
    return hashlib.sha256(f"{standard_id}\n{rule_id}\n{endpoint}".encode()).hexdigest()[:32]


def _rule_descriptor(standard: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    reference = finding["reference"]
    description = f"{standard['short_name']} ({standard['edition']}) — {reference}"
    help_text = finding["remediation"] or f"See {reference}."
    descriptor: dict[str, Any] = {
        "id": f"{standard['id']}/{finding['rule_id']}",
        "shortDescription": {"text": finding["title"]},
        "fullDescription": {"text": f"{finding['title']}. Source: {description}"},
        "help": {
            "text": help_text,
            "markdown": f"{help_text}\n\nSource: {description}\n\n<{standard['url']}>",
        },
        "helpUri": standard["url"],
        "defaultConfiguration": {"level": DEFAULT_LEVEL.get(finding["severity"], "note")},
        "properties": {
            "tags": ["security", "tls", standard["short_name"], finding["control"]],
            "security-severity": SECURITY_SEVERITY.get(finding["severity"], "1.0"),
            "standard": standard["id"],
            "control": finding["control"],
            "reference": reference,
        },
    }
    return descriptor


def _message(finding: dict[str, Any], standard: dict[str, Any]) -> str:
    parts = [f"{finding['title']}: {finding['message']}."]
    if finding["evidence"]:
        shown = ", ".join(finding["evidence"][:12])
        if len(finding["evidence"]) > 12:
            shown += f", and {len(finding['evidence']) - 12} more"
        parts.append(f"Found: {shown}.")
    if finding["remediation"]:
        parts.append(f"Fix: {finding['remediation']}")
    parts.append(f"Reference: {standard['short_name']} — {finding['reference']}.")
    return " ".join(parts)


def build(report: dict[str, Any]) -> dict[str, Any]:
    """Render a report as a SARIF 2.1.0 log."""
    observation = report["observation"]
    target = observation["target"]
    endpoint = _endpoint(target)

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for evaluation in report["evaluations"]:
        standard = evaluation["standard"]
        for finding in evaluation["findings"]:
            descriptor = _rule_descriptor(standard, finding)
            rule_id = descriptor["id"]
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append(descriptor)

            level = LEVELS.get(finding["status"])
            if level is None:
                continue  # pass and not_applicable are not problems
            results.append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_index[rule_id],
                    "level": level,
                    "message": {"text": _message(finding, standard)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f"tls://{endpoint}",
                                    "description": {"text": "Audited TLS endpoint"},
                                }
                            },
                            "logicalLocations": [
                                {"fullyQualifiedName": endpoint, "kind": "resource"}
                            ],
                        }
                    ],
                    "partialFingerprints": {
                        "tr02102AuditFindingV1": _fingerprint(
                            standard["id"], finding["rule_id"], endpoint
                        )
                    },
                    "properties": {
                        "status": finding["status"],
                        "severity": finding["severity"],
                        "standard": standard["id"],
                        "standardEdition": standard["edition"],
                        "control": finding["control"],
                        "transcription": standard["transcription"],
                    },
                }
            )

    notifications = [
        {"level": "note", "message": {"text": note}} for note in observation.get("notes", [])
    ]
    if not observation.get("complete", True):
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": "The scan did not complete; unfinished checks are reported as notes, "
                    "never as passes."
                },
            }
        )

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tr02102-audit",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"tr02102-audit/tls/{endpoint}"},
                "invocations": [
                    {
                        "executionSuccessful": bool(observation.get("complete", True)),
                        "startTimeUtc": _sarif_time(str(observation.get("collected_at", ""))),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
                "properties": {
                    "target": endpoint,
                    "resolvedAddress": target.get("ip"),
                    "evaluatedOn": report["evaluated_on"],
                    "observationSha256": report["observation_sha256"],
                    "standards": [e["standard"]["id"] for e in report["evaluations"]],
                },
            }
        ],
    }
