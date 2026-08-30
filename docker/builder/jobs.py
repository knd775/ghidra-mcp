"""In-process job queue for the builder HTTP control plane.

POST /build returns a job_id immediately. A single worker runs compiles so
two framework builds do not thrash the box. GET /build/{id} is how a
caller that cannot wait out an MCP hop retrieves the result.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable

RETAINED = 64


class Job:
    def __init__(self, job_id: str, request: dict[str, Any]) -> None:
        self.id = job_id
        self.request = request
        self.status = "queued"  # queued | running | done | failed
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self.submitted_ms = int(time.time() * 1000)
        self.started_ms = 0
        self.finished_ms = 0
        self.lock = threading.Lock()

    def snapshot(self, *, include_result: bool = True) -> dict[str, Any]:
        with self.lock:
            body: dict[str, Any] = {
                "ok": self.status != "failed",
                "job_id": self.id,
                "status": self.status,
                "submitted_ms_ago": int(time.time() * 1000) - self.submitted_ms,
            }
            if self.status == "running" and self.started_ms:
                body["running_ms"] = int(time.time() * 1000) - self.started_ms
            if self.status in {"done", "failed"} and self.finished_ms and self.started_ms:
                body["took_ms"] = self.finished_ms - self.started_ms
            if self.status == "failed" and self.error:
                body["error"] = self.error
            if include_result and self.result is not None:
                body["result"] = self.result
            return body


class JobQueue:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._order: deque[str] = deque()
        self._pending: deque[str] = deque()
        self._cv = threading.Condition()
        self._counter = 0
        self._worker: threading.Thread | None = None
        self._run: Callable[..., Any] | None = None
        self._src_cache = None
        self._handle: Callable[..., dict[str, Any]] | None = None
        self._error_payload: Callable[[BaseException], dict[str, Any]] | None = None

    def start(
        self,
        *,
        handle: Callable[..., dict[str, Any]],
        error_payload: Callable[[BaseException], dict[str, Any]],
        run: Callable[..., Any],
        src_cache: Any,
    ) -> None:
        self._handle = handle
        self._error_payload = error_payload
        self._run = run
        self._src_cache = src_cache
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._loop, name="builder-job-worker", daemon=True)
            self._worker.start()

    def submit(self, request: dict[str, Any]) -> Job:
        with self._cv:
            self._counter += 1
            job_id = f"build-{self._counter}-{int(time.time() * 1000) & 0xFFFF:x}"
            job = Job(job_id, request)
            self._jobs[job_id] = job
            self._order.append(job_id)
            self._pending.append(job_id)
            while len(self._order) > RETAINED + len(self._pending) + 8:
                old = self._order.popleft()
                kept = self._jobs.get(old)
                if kept is not None and kept.status in {"queued", "running"}:
                    self._order.appendleft(old)
                    break
                self._jobs.pop(old, None)
            self._cv.notify()
            return job

    def get(self, job_id: str) -> Job | None:
        with self._cv:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._cv:
            jobs = [self._jobs[i] for i in self._order if i in self._jobs]
        return [j.snapshot(include_result=False) for j in jobs]

    def _loop(self) -> None:
        while True:
            with self._cv:
                while not self._pending:
                    self._cv.wait()
                job_id = self._pending.popleft()
                job = self._jobs.get(job_id)
            if job is None or self._handle is None:
                continue
            with job.lock:
                job.status = "running"
                job.started_ms = int(time.time() * 1000)
            try:
                result = self._handle(
                    job.request, run=self._run, src_cache=self._src_cache
                )
                with job.lock:
                    job.result = result
                    job.status = "done"
                    job.finished_ms = int(time.time() * 1000)
            except Exception as exc:  # noqa: BLE001 — payload is the API
                payload = self._error_payload(exc) if self._error_payload else {
                    "ok": False,
                    "error": str(exc),
                    "status": "internal_error",
                }
                with job.lock:
                    job.result = payload
                    job.error = str(exc)
                    job.status = "failed"
                    job.finished_ms = int(time.time() * 1000)
