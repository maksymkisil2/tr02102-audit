"""Command-line interface.

tr02102-audit scan example.org            # all standards, text report
tr02102-audit scan example.org:8443 --standard bsi-tr-02102-2 --format json
tr02102-audit evaluate saved-report.json  # re-evaluate stored observations
tr02102-audit standards                   # list available standards
tr02102-audit serve                       # web interface
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from tr02102_audit import __version__, report, sarif
from tr02102_audit.exit_codes import ExitCode
from tr02102_audit.netguard import TargetError, parse_target, resolve
from tr02102_audit.scan import scan_tls
from tr02102_audit.standards import Standard, load_builtin

PROG = "tr02102-audit"
SEVERITIES = ("info", "low", "medium", "high")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Audit TLS configuration against BSI TR-02102 and other standards.",
        epilog="For authorised use only: audit systems you own or are permitted to test.",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_output_options(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "-s",
            "--standard",
            action="append",
            metavar="ID",
            help="standard to evaluate against (repeatable; default: all)",
        )
        p.add_argument(
            "-f",
            "--format",
            choices=("text", "json", "sarif"),
            default="text",
            help="sarif suits CI dashboards such as GitHub code scanning",
        )
        p.add_argument("-o", "--output", type=Path, help="write the report to this file")
        p.add_argument(
            "--fail-on",
            choices=SEVERITIES,
            default="medium",
            help="exit with 1 if a failed check has at least this severity (default: medium)",
        )

    scan = sub.add_parser("scan", help="scan a TLS endpoint")
    scan.add_argument("target", help="host, host:port or [ipv6]:port")
    scan.add_argument(
        "--public-only",
        action="store_true",
        help="refuse private, loopback and reserved addresses (as the web service does)",
    )
    add_output_options(scan)

    ev = sub.add_parser("evaluate", help="re-evaluate a saved JSON report or observation")
    ev.add_argument("file", type=Path)
    add_output_options(ev)

    sub.add_parser("standards", help="list available standards")

    serve = sub.add_parser("serve", help="run the web interface")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def _select(ids: Sequence[str] | None) -> list[Standard]:
    available = load_builtin()
    if not ids:
        return list(available.values())
    unknown = [i for i in ids if i not in available]
    if unknown:
        raise SystemExit(f"unknown standard: {', '.join(unknown)} (see '{PROG} standards')")
    return [available[i] for i in ids]


def _emit(rep: dict[str, object], args: argparse.Namespace) -> int:
    if args.format == "json":
        text = json.dumps(rep, indent=2) + "\n"
    elif args.format == "sarif":
        text = json.dumps(sarif.build(rep), indent=2) + "\n"
    else:
        text = report.render_text(rep)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        args.output.chmod(0o600)  # reports describe weaknesses (threat T-07)
    else:
        sys.stdout.write(text)

    if not rep["observation"]["complete"]:  # type: ignore[index]
        return ExitCode.ERROR
    worst = report.worst_failure_severity(rep)
    if worst is not None and SEVERITIES.index(worst) >= SEVERITIES.index(args.fail_on):
        return ExitCode.FINDINGS
    return ExitCode.OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "standards":
        for std in load_builtin().values():
            meta = f"{std.edition}, {len(std.rules)} rules, {std.transcription}"
            print(f"{std.id:24} {std.title} ({meta})")
        return ExitCode.OK

    if args.command == "scan":
        standards = _select(args.standard)
        try:
            host, port = parse_target(args.target)
            target = resolve(host, port, allow_private=not args.public_only)
        except TargetError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return ExitCode.ERROR
        observation = scan_tls(target)
        return _emit(report.build(observation, standards), args)

    if args.command == "evaluate":
        standards = _select(args.standard)
        data = json.loads(args.file.read_text(encoding="utf-8"))
        observation = data.get("observation", data)
        return _emit(report.build(observation, standards), args)

    if args.command == "serve":
        from tr02102_audit.web import create_app

        create_app().run(host=args.host, port=args.port)
        return ExitCode.OK

    # No command: nothing was audited, so the run must not look like a success.
    parser.print_help(sys.stderr)
    return ExitCode.ERROR
