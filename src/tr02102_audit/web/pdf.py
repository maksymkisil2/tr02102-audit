"""The report as a PDF file: summary, action plan, comparison, evidence.

Built with reportlab from the same report dictionary as the web page, so the
two cannot disagree. The layout follows an inspection report: what was
checked and the result first, then what to do, then the evidence.

Everything that comes from the scanned server (host names, certificate
fields, cipher names) is escaped before it reaches reportlab's markup parser,
as on the web page (threat T-13).

Texts go through ``tr``, the translation function of the web interface. The
command line passes one that returns the English text.
"""

import io
from collections.abc import Callable, Mapping, Sequence
from functools import cache
from importlib import resources
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from tr02102_audit import __version__, advice

Translate = Callable[..., str]

INK = colors.HexColor("#1d2433")
QUIET = colors.HexColor("#5b6475")
RULE = colors.HexColor("#d5d9e2")
STAMP = colors.HexColor("#2b3a8c")
TINT = colors.HexColor("#eef0f7")
GOOD = colors.HexColor("#2e7d4f")
BAD = colors.HexColor("#b3261e")
WARN = colors.HexColor("#9a5b00")
FAIR = colors.HexColor("#56780f")
GOOD_BG = colors.HexColor("#e2f3ec")
BAD_BG = colors.HexColor("#fbe7e5")
WARN_BG = colors.HexColor("#fbefd5")

_GRADE_COLOUR = {"A+": GOOD, "A": GOOD, "B": FAIR, "C": WARN, "F": BAD}
_PRIORITY_COLOUR = {"critical": BAD, "high": BAD, "medium": WARN, "low": QUIET}
_STATUS_COLOUR = {"pass": GOOD, "fail": BAD, "warn": WARN}
_STATUS_TINT = {"fail": BAD_BG, "warn": WARN_BG}
_VERDICT_TINT = {"pass": GOOD_BG, "pass_with_warnings": WARN_BG, "fail": BAD_BG}
_VERDICT_COLOUR = {"pass": GOOD, "pass_with_warnings": WARN, "fail": BAD}
# The frame of SimpleDocTemplate keeps 6 pt of padding on each side.
_FRAME_PADDING = 12


def _english(text: str, **params: Any) -> str:
    return text % params if params else text


@cache
def _fonts() -> tuple[str, str, str]:
    folder = resources.files("tr02102_audit").joinpath("fonts")
    for name, file in (
        ("Sans", "DejaVuSans.ttf"),
        ("Sans-Bold", "DejaVuSans-Bold.ttf"),
        ("Mono", "DejaVuSansMono.ttf"),
    ):
        with resources.as_file(folder.joinpath(file)) as path:
            pdfmetrics.registerFont(TTFont(name, str(path)))
    pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold")
    return "Sans", "Sans-Bold", "Mono"


def _styles() -> dict[str, ParagraphStyle]:
    sans, bold, mono = _fonts()
    base = ParagraphStyle("base", fontName=sans, fontSize=9, leading=12.5, textColor=INK)
    return {
        "base": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.8, leading=10.5, textColor=QUIET),
        "title": ParagraphStyle("title", parent=base, fontName=bold, fontSize=18, leading=22),
        "h1": ParagraphStyle(
            "h1",
            parent=base,
            fontName=bold,
            fontSize=12.5,
            leading=16,
            spaceBefore=10,
            spaceAfter=5,
            textColor=STAMP,
        ),
        "h2": ParagraphStyle("h2", parent=base, fontName=bold, fontSize=10, leading=13.5),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=10.5),
        "cellb": ParagraphStyle("cellb", parent=base, fontName=bold, fontSize=8, leading=10.5),
        "mono": ParagraphStyle(
            "mono", parent=base, fontName=mono, fontSize=7, leading=9.2, textColor=INK
        ),
        "figure": ParagraphStyle(
            "figure", parent=base, fontName=bold, fontSize=17, leading=20, textColor=INK
        ),
        "figure0": ParagraphStyle("figure0", parent=base, fontSize=17, leading=20, textColor=QUIET),
        "lead": ParagraphStyle("lead", parent=base, fontSize=10, leading=14),
        "tiny": ParagraphStyle("tiny", parent=base, fontSize=6.8, leading=8.6),
        "tinyb": ParagraphStyle("tinyb", parent=base, fontName=bold, fontSize=6.8, leading=8.6),
        "tag": ParagraphStyle(
            "tag",
            parent=base,
            fontName=bold,
            fontSize=7.5,
            leading=9.5,
            alignment=TA_CENTER,
            textColor=colors.white,
        ),
    }


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _seal(grade: str | None) -> Drawing:
    size = 30 * mm
    colour = _GRADE_COLOUR.get(grade or "", QUIET)
    drawing = Drawing(size, size)
    drawing.add(
        Circle(
            size / 2, size / 2, size / 2 - 2, strokeColor=colour, strokeWidth=2.2, fillColor=None
        )
    )
    drawing.add(
        Circle(
            size / 2, size / 2, size / 2 - 6, strokeColor=colour, strokeWidth=0.6, fillColor=None
        )
    )
    _, bold, _ = _fonts()
    text = grade or "–"
    drawing.add(
        String(
            size / 2,
            size / 2 - 9,
            text,
            fontName=bold,
            fontSize=26,
            fillColor=colour,
            textAnchor="middle",
        )
    )
    return drawing


def _grid(rows: list[list[Any]], widths: Sequence[float], *, header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    if header:
        style += [("LINEBELOW", (0, 0), (-1, 0), 0.9, INK)]
    table.setStyle(TableStyle(style))
    return table


def _verdict_text(verdict: str, tr: Translate) -> str:
    return {
        "pass": tr("Conforms"),
        "pass_with_warnings": tr("Conforms, with warnings"),
        "fail": tr("Does not conform"),
        "incomplete": tr("Incomplete"),
    }.get(verdict, verdict)


def _status_text(status: str | None, tr: Translate) -> str:
    return {
        "pass": tr("Met"),
        "fail": tr("Not met"),
        "warn": tr("Warning"),
        "inconclusive": tr("Unknown"),
        "not_applicable": tr("Not applicable"),
        None: "·",
    }.get(status, str(status))


def _priority_text(priority: str, tr: Translate) -> str:
    return tr(advice.PRIORITY_TEXT[priority])


def build(report: Mapping[str, Any], tr: Translate = _english) -> bytes:
    """Render ``report`` (from ``report.build``) as a PDF document."""
    st = _styles()
    obs = report["observation"]
    target = obs["target"]
    facts = obs["facts"]
    tls = facts["tls"]
    cert = facts.get("certificate") or {}
    rate = report["rating"]
    actions = advice.plan(report)
    numbers = advice.summary(report, actions)
    width = A4[0] - 36 * mm - _FRAME_PADDING
    where = f"{target['host']}:{target['port']}"

    story: list[Any] = []

    # ------------------------------------------------------------ cover block
    meta = [
        [_p(tr("Server"), st["small"]), _p(f"{where} ({target['ip']})", st["cellb"])],
        [
            _p(tr("Checked"), st["small"]),
            _p(str(obs["collected_at"])[:19].replace("T", " ") + " UTC", st["cell"]),
        ],
        [
            _p(tr("Measurement"), st["small"]),
            _p(
                tr("%(n)s connections", n=obs["connections"]) + f" · {obs['duration_s']} s",
                st["cell"],
            ),
        ],
        [_p(tr("Tool"), st["small"]), _p(f"tr02102-audit {__version__}", st["cell"])],
    ]
    head = Table(
        [
            [
                [
                    _p(tr("TLS audit report"), st["title"]),
                    Spacer(1, 4),
                    _p(tr("TLS audit against recognised standards"), st["small"]),
                    Spacer(1, 8),
                    _grid(meta, (32 * mm, width - 70 * mm), header=False),
                ],
                _seal(rate.get("grade")),
            ]
        ],
        colWidths=(width - 34 * mm, 34 * mm),
    )
    head.setStyle(
        TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)])
    )
    story += [head, Spacer(1, 6)]

    if not obs.get("complete", True):
        story.append(
            _p(
                tr("The check is incomplete.")
                + " "
                + "; ".join(str(x) for x in obs.get("incomplete", [])),
                st["base"],
            )
        )

    # -------------------------------------------------------------- at a glance
    story.append(_tally(rate.get("grade"), numbers, st, width, tr))
    story.append(Spacer(1, 8))
    if rate.get("reasons"):
        story.append(_p(tr("Why the rating is not better:"), st["h2"]))
        story.append(Spacer(1, 2))
        story.append(_reasons(rate["reasons"], st, width, tr))
    elif rate.get("grade"):
        line = "<b>" + escape(tr("No weakness found.")) + "</b>"
        if rate.get("bonus_missing"):
            missing = "; ".join(tr(b["title"]) for b in rate["bonus_missing"])
            line += " " + escape(tr("An A+ would also need:") + " " + missing) + "."
        story.append(Paragraph(line, st["lead"]))
    elif rate.get("at_best") is None:
        story.append(
            _p(
                tr("Not rated.") + " " + tr("Nothing could be measured, so there is no rating."),
                st["lead"],
            )
        )
    else:
        story.append(
            _p(
                tr("Not rated.")
                + " "
                + tr(
                    "The check left something open, and an unknown is never counted as good. On what was measured the rating would be %(grade)s at best.",
                    grade=rate.get("at_best"),
                ),
                st["lead"],
            )
        )

    # ------------------------------------------------------------ conformance
    story.append(_p(tr("Conformance"), st["h1"]))
    rows: list[list[Any]] = [
        [
            _p(tr("Standard"), st["cellb"]),
            _p(tr("Verdict"), st["cellb"]),
            _p(tr("Requirements not met"), st["cellb"]),
            _p(tr("Warnings"), st["cellb"]),
        ]
    ]
    tints: list[tuple[Any, ...]] = []
    for index, ev in enumerate(report["evaluations"], 1):
        verdict = [
            Paragraph(
                f'<font color="{_VERDICT_COLOUR.get(ev["verdict"], QUIET).hexval()}">'
                f"{escape(_verdict_text(ev['verdict'], tr))}</font>",
                st["cellb"],
            )
        ]
        if ev.get("off_list_only"):
            verdict.append(
                _p(tr("Only because of its approved list; no weak algorithm found."), st["small"])
            )
        rows.append(
            [
                Paragraph(
                    f"<b>{escape(ev['standard']['short_name'])}</b> "
                    f'<font color="{QUIET.hexval()}">{escape(ev["standard"]["edition"])}</font>',
                    st["cell"],
                ),
                verdict,
                _p(ev["counts"]["fail"], st["cell"]),
                _p(ev["counts"]["warn"], st["cell"]),
            ]
        )
        tint = _VERDICT_TINT.get(ev["verdict"])
        if tint is not None:
            tints.append(("BACKGROUND", (1, index), (1, index), tint))
    table = _grid(rows, (width * 0.36, width * 0.36, width * 0.16, width * 0.12))
    table.setStyle(TableStyle(tints))
    story.append(table)
    story.append(Spacer(1, 4))
    story.append(
        _p(
            tr(
                "The rating above is this tool’s own summary. The verdicts below follow each standard’s own wording: what it requires is a failure when missing, what it recommends is a warning."
            ),
            st["small"],
        )
    )

    # ------------------------------------------------------------ action plan
    story.append(CondPageBreak(60 * mm))
    story.append(_p(tr("What to do, in this order"), st["h1"]))
    if not actions:
        story.append(_p(tr("No weakness found."), st["base"]))
    for number, action in enumerate(actions, 1):
        story.append(_action(number, action, st, width, tr))

    profiles = []
    for profile in ("compatible", "strict"):
        name, note = advice.PROFILE_TEXT[profile]
        config = advice.configuration(profile)
        block = [_p(f"{tr(name)}: {tr(note)}", st["h2"]), Spacer(1, 2)]
        for server in ("nginx", "apache"):
            block.append(_p(server, st["small"]))
            block.append(_code(config[server], st, width))
            block.append(Spacer(1, 3))
        profiles.append(KeepTogether(block))
    story.append(CondPageBreak(70 * mm))
    story.append(_p(tr("Recommended configuration"), st["h1"]))
    story.append(
        _p(
            tr(
                "Both profiles are taken from the project’s test lab, where every push checks them against the standards."
            ),
            st["small"],
        )
    )
    story.append(Spacer(1, 4))
    story += profiles

    # ------------------------------------------------------------- comparison
    comparison = report["comparison"]
    if comparison["rows"]:
        story.append(CondPageBreak(60 * mm))
        story.append(_p(tr("Control by control"), st["h1"]))
        names = comparison["standards"]
        # A non-breaking hyphen keeps "TR-02102-2" in one piece in a narrow column.
        head_row = [_p(tr("Topic"), st["tinyb"])] + [
            _p(n.replace("-", "\u2011"), st["tinyb"]) for n in names
        ]
        grid_rows: list[list[Any]] = [head_row]
        tints.clear()
        for index, row in enumerate(comparison["rows"], 1):
            cells = [_p(tr(row["label"]), st["cell"])]
            for column, status in enumerate(row["cells"], 1):
                colour = _STATUS_COLOUR.get(status or "", QUIET)
                text = "–" if status == "not_applicable" else _status_text(status, tr)
                cells.append(
                    Paragraph(
                        f'<font color="{colour.hexval()}">{escape(text)}</font>',
                        st["cellb"] if status in ("fail", "warn") else st["cell"],
                    )
                )
                if status in _STATUS_TINT:
                    tints.append(
                        ("BACKGROUND", (column, index), (column, index), _STATUS_TINT[status])
                    )
            grid_rows.append(cells)
        first = width * 0.22
        rest = (width - first) / max(1, len(names))
        matrix = _grid(grid_rows, (first, *([rest] * len(names))))
        matrix.setStyle(TableStyle(tints))
        story.append(
            _p(
                tr("One row per topic, one column per standard.")
                + " – "
                + tr("not applicable to this server")
                + "; · "
                + tr("the standard has no rule for it")
                + ".",
                st["small"],
            )
        )
        story.append(Spacer(1, 3))
        story.append(matrix)

    # ------------------------------------------------------- measured facts
    story.append(CondPageBreak(60 * mm))
    story.append(_p(tr("What the server accepts"), st["h1"]))
    fact_rows: list[list[Any]] = [
        [
            _p(tr("Protocol versions"), st["cellb"]),
            _p(", ".join(tls.get("protocol_versions") or []) or "–", st["cell"]),
        ],
    ]
    for key, label in (
        ("tls13", tr("TLS 1.3 cipher suites")),
        ("tls12", tr("TLS 1.2 cipher suites")),
    ):
        suites = (tls.get("suites") or {}).get(key) or []
        if suites:
            fact_rows.append([_p(label, st["cellb"]), _p(", ".join(suites), st["mono"])])
    for key in ("tls13", "tls12"):
        groups = (tls.get("groups") or {}).get(key) or []
        if groups:
            fact_rows.append(
                [
                    _p(
                        tr("Key-exchange groups") + f" ({key.upper()[:3]} 1.{key[-1]})", st["cellb"]
                    ),
                    _p(", ".join(groups), st["mono"]),
                ]
            )
    flags = [
        (tr("Extended master secret"), tls.get("extended_master_secret")),
        (tr("Secure renegotiation"), tls.get("secure_renegotiation")),
        (tr("TLS compression"), tls.get("compression")),
    ]
    for label, value in flags:
        shown = tr("yes") if value is True else tr("no") if value is False else tr("unknown")
        fact_rows.append([_p(label, st["cellb"]), _p(shown, st["cell"])])
    if cert:
        key = f"{cert.get('key_type')} {cert.get('key_bits')}" + (
            f" {cert['curve']}" if cert.get("curve") else ""
        )
        fact_rows += [
            [_p(tr("Issued to"), st["cellb"]), _p(cert.get("subject_cn") or "–", st["cell"])],
            [_p(tr("Issued by"), st["cellb"]), _p(cert.get("issuer_cn") or "–", st["cell"])],
            [_p(tr("Key"), st["cellb"]), _p(key, st["cell"])],
            [
                _p(tr("Signature"), st["cellb"]),
                _p(cert.get("signature_algorithm") or "–", st["cell"]),
            ],
            [
                _p(tr("Valid"), st["cellb"]),
                _p(
                    f"{str(cert.get('not_before'))[:10]} {tr('to')} {str(cert.get('not_after'))[:10]}",
                    st["cell"],
                ),
            ],
            [
                _p(tr("Trust"), st["cellb"]),
                _p(
                    tr("verified")
                    if cert.get("trusted")
                    else f"{tr('not trusted')}: {cert.get('trust_error') or ''}",
                    st["cell"],
                ),
            ],
        ]
    else:
        fact_rows.append(
            [
                _p(tr("Certificate"), st["cellb"]),
                _p(tr("No certificate could be retrieved."), st["cell"]),
            ]
        )
    story.append(_grid(fact_rows, (width * 0.34, width * 0.66), header=False))

    # --------------------------------------------------------------- findings
    for ev in report["evaluations"]:
        open_findings = [
            f for f in ev["findings"] if f["status"] in ("fail", "warn", "inconclusive")
        ]
        std = ev["standard"]
        story.append(CondPageBreak(40 * mm))
        story.append(_p(f"{std['short_name']} · {_verdict_text(ev['verdict'], tr)}", st["h1"]))
        story.append(_p(f"{std['title']} · {std['edition']}", st["small"]))
        if any(f.get("off_list_only") for f in open_findings):
            story.append(
                _p(
                    tr(
                        "Marked “approved list only”: the value is considered sound by other standards, but this one only accepts what is on its own list."
                    ),
                    st["small"],
                )
            )
        story.append(Spacer(1, 3))
        if not open_findings:
            story.append(
                _p(tr("Every requirement and recommendation of this standard is met."), st["base"])
            )
            continue
        tints.clear()
        rows = [
            [
                _p(tr("Rule"), st["cellb"]),
                _p(tr("Result"), st["cellb"]),
                _p(tr("Requirement"), st["cellb"]),
            ]
        ]
        for f in open_findings:
            colour = _STATUS_COLOUR.get(f["status"], QUIET)
            detail = [_p(f["title"], st["cellb"]), _p(f["message"], st["cell"])]
            if f["evidence"]:
                shown = ", ".join(str(x) for x in f["evidence"][:6])
                if len(f["evidence"]) > 6:
                    shown += " " + tr("and %(n)s more", n=len(f["evidence"]) - 6)
                detail.append(_p(shown, st["mono"]))
            detail.append(_p(tr("Fix:") + " " + f["remediation"], st["small"]))
            detail.append(_p(f["reference"], st["small"]))
            level = tr("required") if f.get("level") == "required" else tr("recommended")
            if f.get("off_list_only"):
                level += ", " + tr("approved list only")
            if f["status"] in _STATUS_TINT:
                tints.append(
                    ("BACKGROUND", (1, len(rows)), (1, len(rows)), _STATUS_TINT[f["status"]])
                )
            rows.append(
                [
                    _p(f["rule_id"], st["cell"]),
                    [
                        Paragraph(
                            f'<font color="{colour.hexval()}">'
                            f"{escape(_status_text(f['status'], tr))}</font>",
                            st["cellb"],
                        ),
                        _p(level, st["small"]),
                    ],
                    detail,
                ]
            )
        table = _grid(rows, (width * 0.15, width * 0.17, width * 0.68))
        table.setStyle(TableStyle(tints))
        story.append(table)

    # ------------------------------------------------------- method and limits
    story.append(CondPageBreak(50 * mm))
    story.append(_p(tr("What a report is."), st["h1"]))
    for text in (
        tr(
            "A report is technical evidence about one address at one moment. It is not a certificate and does not replace an audit."
        ),
        tr("Anything that could not be measured is reported as unknown, never as met."),
        tr(
            "This is a view from outside: it shows what this address accepted at the time of the check. Servers behind a load balancer may differ from one another."
        ),
        tr("Rule texts and references are quoted from the standards and stay in English."),
    ):
        story.append(_p(text, st["base"]))
        story.append(Spacer(1, 2))
    story.append(Spacer(1, 4))
    story.append(_p(tr("Fingerprint of the measurement (SHA-256):"), st["small"]))
    story.append(_p(report["observation_sha256"], st["mono"]))

    buffer = io.BytesIO()
    footer = f"tr02102-audit {__version__} · {where}"

    def on_page(canvas: Any, doc: Any) -> None:
        sans, _, _ = _fonts()
        canvas.saveState()
        canvas.setFont(sans, 7)
        canvas.setFillColor(QUIET)
        canvas.drawString(18 * mm, 10 * mm, footer)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, str(doc.page))
        canvas.setStrokeColor(STAMP)
        canvas.setLineWidth(1.4)
        canvas.line(18 * mm, A4[1] - 12 * mm, A4[0] - 18 * mm, A4[1] - 12 * mm)
        canvas.restoreState()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title=f"TLS audit report {where}",
        author="tr02102-audit",
        subject=tr("TLS audit against recognised standards"),
        creator=f"tr02102-audit {__version__}",
    )
    document.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buffer.getvalue()


def _code(lines: Sequence[str], st: Mapping[str, ParagraphStyle], width: float) -> Table:
    body = "<br/>".join(escape(line) for line in lines)
    box = Table([[Paragraph(body, st["mono"])]], colWidths=(width,))
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), TINT),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return box


def _action(
    number: int,
    action: Mapping[str, Any],
    st: Mapping[str, ParagraphStyle],
    width: float,
    tr: Translate,
) -> KeepTogether:
    """One step of the plan, with a bar in its priority colour down the left."""
    colour = _PRIORITY_COLOUR[action["priority"]]
    inner = width - 9
    head = (
        f'<font color="{colour.hexval()}">{escape(_priority_text(action["priority"], tr).upper())}</font>'
        f"  {number}. {escape(tr(action['title']))}"
    )
    parts: list[Any] = [
        Paragraph(head, st["h2"]),
        Spacer(1, 2),
        _p(tr(action["reason"]), st["base"]),
    ]
    notes = []
    if action["rating_cap"]:
        notes.append(tr("Caps the rating at %(grade)s.", grade=action["rating_cap"]))
    if action["off_list_only"]:
        notes.append(
            tr("Needed only for conformity with an approved list; the current choice is not weak.")
        )
    if notes:
        parts.append(_p(" ".join(notes), st["small"]))
    facts: list[list[Any]] = []
    if action["evidence"]:
        shown = ", ".join(action["evidence"][:8])
        if len(action["evidence"]) > 8:
            shown += " " + tr("and %(n)s more", n=len(action["evidence"]) - 8)
        facts.append([_p(tr("Found:"), st["cellb"]), _p(shown, st["mono"])])
    for status, label in advice.ROLE_TEXT.items():
        names = [a["standard"] for a in action["affected"] if a["status"] == status]
        if names:
            facts.append([_p(tr(label), st["cellb"]), _p(", ".join(names), st["cell"])])
    if facts:
        table = Table(facts, colWidths=(34 * mm, inner - 34 * mm), hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                ]
            )
        )
        parts += [Spacer(1, 3), table]
    if action.get("same_as"):
        parts.append(
            _p(tr("Same configuration as action %(n)s.", n=action["same_as"]), st["small"])
        )
    else:
        snippets = [(server, lines) for server, lines in action["snippets"].items() if lines]
        if snippets:
            parts.append(Spacer(1, 4))
            parts.append(_snippets(snippets, st, inner))
    box = Table([[parts]], colWidths=(width,))
    box.setStyle(
        TableStyle(
            [
                ("LINEBEFORE", (0, 0), (0, 0), 3, colour),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return KeepTogether([Spacer(1, 7), box])


def _snippets(
    snippets: Sequence[tuple[str, Sequence[str]]],
    st: Mapping[str, ParagraphStyle],
    width: float,
) -> Table:
    """Configuration blocks; nginx and Apache side by side."""
    gap = 6
    column = (width - gap * (len(snippets) - 1)) / len(snippets)
    cells: list[Any] = []
    widths: list[float] = []
    for index, (server, lines) in enumerate(snippets):
        if index:
            cells.append("")
            widths.append(gap)
        cells.append([_p(server, st["small"]), _code(lines, st, column)])
        widths.append(column)
    table = Table([cells], colWidths=widths, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return table


def _tally(
    grade: str | None,
    numbers: Mapping[str, Any],
    st: Mapping[str, ParagraphStyle],
    width: float,
    tr: Translate,
) -> Table:
    """The key figures: rating, standards met, steps by priority."""
    cells = [
        (tr("Rating"), grade or "–", _GRADE_COLOUR.get(grade or "", QUIET), True),
        (
            tr("Standards met"),
            tr("%(met)s of %(all)s", met=numbers["conform"], all=numbers["standards"]),
            INK,
            True,
        ),
    ]
    for priority in advice.PRIORITIES:
        count = numbers["actions"][priority]
        colour = _PRIORITY_COLOUR[priority] if count else RULE
        cells.append((_priority_text(priority, tr), str(count), colour, bool(count)))
    row = [
        [_p(label, st["small"]), _p(value, st["figure"] if strong else st["figure0"])]
        for label, value, _, strong in cells
    ]
    first = width * 0.14
    second = width * 0.2
    rest = (width - first - second) / 4
    table = Table([row], colWidths=(first, second, rest, rest, rest, rest))
    style: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]
    for column, (_, _, colour, _) in enumerate(cells):
        style.append(("LINEABOVE", (column, 0), (column, 0), 2.4, colour))
    table.setStyle(TableStyle(style))
    return table


def _reasons(
    reasons: Sequence[Mapping[str, Any]],
    st: Mapping[str, ParagraphStyle],
    width: float,
    tr: Translate,
) -> Table:
    """Why the rating is not better: one line per cap, with the grade it sets."""
    rows = []
    style: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]
    for index, reason in enumerate(reasons):
        title = tr(reason["title"])
        if reason.get("detail"):
            title += f" ({reason['detail']})"
        rows.append([_p(reason["grade"], st["tag"]), _p(title, st["base"])])
        colour = _GRADE_COLOUR.get(reason["grade"], QUIET)
        style.append(("BACKGROUND", (0, index), (0, index), colour))
        style.append(("LEFTPADDING", (1, index), (1, index), 7))
    table = Table(rows, colWidths=(7 * mm, width - 7 * mm), hAlign="LEFT")
    table.setStyle(TableStyle(style))
    return table
