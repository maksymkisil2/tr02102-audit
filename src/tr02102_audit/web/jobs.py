"""Background scan jobs.

A scan takes seconds to a minute, longer than an HTTP request should wait.
Jobs run in a small thread pool; the report page refreshes until the job is
done. The state of every job lives in the database, so a report survives a
restart and the history shows what was scanned.
"""

import contextlib
import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from tr02102_audit import report
from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.scan import scan_tls
from tr02102_audit.standards import Standard
from tr02102_audit.web.store import Store, StoreError

ScanFn = Callable[[ResolvedTarget], dict[str, Any]]
DoneFn = Callable[[str, str], None]  # (public id, outcome text)


class JobRunner:
    def __init__(self, store: Store, max_workers: int = 2) -> None:
        self._store = store
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")
        self._lock = threading.Lock()
        self._pending = 0
        self._max_pending = max_workers * 3

    def close(self) -> None:
        """Wait for running jobs and stop the workers."""
        self._pool.shutdown(wait=True)

    def busy(self) -> bool:
        with self._lock:
            return self._pending >= self._max_pending

    def submit(
        self,
        public_id: str,
        target: ResolvedTarget,
        standards: Sequence[Standard],
        scan_fn: ScanFn | None,
        on_done: DoneFn,
    ) -> None:
        with self._lock:
            self._pending += 1
        self._pool.submit(
            self._run, public_id, target, list(standards), scan_fn or scan_tls, on_done
        )

    def _run(
        self,
        public_id: str,
        target: ResolvedTarget,
        standards: list[Standard],
        scan_fn: ScanFn,
        on_done: DoneFn,
    ) -> None:
        outcome = "error"
        try:
            self._store.set_scan_status(public_id, "running")
            observation = scan_fn(target)
            rep = report.build(observation, standards)
            grade = rep["rating"]["grade"]
            self._store.finish_scan(
                public_id,
                observation=observation,
                grade=grade,
                verdicts={e["standard"]["id"]: e["verdict"] for e in rep["evaluations"]},
            )
            outcome = f"rating {grade or 'not rated'}"
        except Exception as exc:  # the job must always reach a final state
            outcome = f"scan failed: {exc.__class__.__name__}"
            with contextlib.suppress(StoreError):
                self._store.finish_scan(public_id, error=outcome)
        finally:
            with self._lock:
                self._pending -= 1
            with contextlib.suppress(StoreError):
                on_done(public_id, outcome)
