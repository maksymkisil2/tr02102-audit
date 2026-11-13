"""Process exit codes.

These values are a public contract: CI pipelines branch on them, so they must
not change between releases. See docs/ARCHITECTURE.md, section 7.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Outcome of a run, as reported to the calling process."""

    OK = 0
    """No finding at or above the configured severity threshold."""

    FINDINGS = 1
    """At least one finding at or above the threshold."""

    ERROR = 2
    """Usage error, scan error or inconclusive result. Never read this as a pass."""
