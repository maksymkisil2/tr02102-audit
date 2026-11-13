"""Background scan jobs, kept in memory.

A scan takes seconds to a minute, longer than an HTTP request should wait.
Jobs run in a small thread pool; the report page polls until the job is done.
State lives in memory, which suits a single-instance free-tier deployment:
reports disappear on restart, and nothing about scanned systems is persisted.
"""

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from tr02102_audit import report
from tr02102_audit.netguard import ResolvedTarget
from tr02102_audit.scan import scan_tls
from tr02102_audit.standards import Standard

ScanFn = Callable[[ResolvedTarget], dict[str, Any]]


@dataclass(slots=True)
class Job:
    id: str
    target: ResolvedTarget
    created: float
    status: str = "queued"  # queued, running, done, error
    report: dict[str, Any] | None = None
    error: str | None = None


class JobStore:
    def __init__(self, max_workers: int, max_jobs: int) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.Lock()
        self._max_jobs = max_jobs
        self._max_pending = max_workers * 3

    def submit(
        self, target: ResolvedTarget, standards: Sequence[Standard], scan_fn: ScanFn | None
    ) -> str | None:
        """Queue a scan; returns None when too many scans are already waiting."""
        with self._lock:
            pending = sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))
            if pending >= self._max_pending:
                return None
            job = Job(id=secrets.token_urlsafe(12), target=target, created=time.time())
            self._jobs[job.id] = job
            while len(self._jobs) > self._max_jobs:
                self._jobs.popitem(last=False)
        self._pool.submit(self._run, job, list(standards), scan_fn or scan_tls)
        return job.id

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    @staticmethod
    def _run(job: Job, standards: list[Standard], scan_fn: ScanFn) -> None:
        job.status = "running"
        try:
            observation = scan_fn(job.target)
            job.report = report.build(observation, standards)
            job.status = "done"
        except Exception as exc:
            job.error = f"scan failed: {exc.__class__.__name__}"
            job.status = "error"
