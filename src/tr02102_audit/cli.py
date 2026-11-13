"""Command-line entry point.

Milestone M0 ships the command skeleton only: the option parser, ``--version``
and the exit-code contract. Scan commands arrive with milestone M1.
"""

import argparse
import sys
from collections.abc import Sequence

from tr02102_audit import __version__
from tr02102_audit.exit_codes import ExitCode

PROG = "tr02102-audit"


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Audit cryptographic configuration against BSI TR-02102.",
        epilog="For authorised use only: audit systems you own or are permitted to test.",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    parser.parse_args(argv)

    # No command exists yet. Nothing was audited, so the run must not look like
    # a success to a calling pipeline: print the help and return ERROR.
    parser.print_help(sys.stderr)
    return ExitCode.ERROR
