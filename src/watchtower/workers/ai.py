"""The AI analysis worker: runs ``ai.analyze`` jobs and nothing else.

It never makes target requests. Before anything connects, it approves the
configured model endpoint (``watchtower.services.ai.endpoint``) and installs
the process egress guard with ``only_allowed``: the database, the broker and
that one exact ``(address, port)`` are reachable, nothing else (no other
loopback or private address, no public internet). The model client is pinned
to the address approved at start, so a later DNS or WSL host change cannot
widen what it reaches; it simply fails until the worker is restarted.

Jobs are capped by ``ai.max_concurrent_analyses`` across all workers through
the ``ai.analyze`` concurrency key.
"""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Callable
from typing import Any

from watchtower.adapters.ai.ollama import OllamaClient
from watchtower.config.settings import Settings
from watchtower.persistence.database import Database
from watchtower.services.ai.endpoint import ResolvedEndpoint, resolve_endpoint
from watchtower.services.jobs import AI_ANALYZE, AI_JOB_KINDS, PipelineAdapters
from watchtower.services.scope import ScopeService
from watchtower.workers import egress
from watchtower.workers.runtime import Worker, default_worker_id

log = logging.getLogger("watchtower.workers.ai")


def approve_endpoint(settings: Settings) -> ResolvedEndpoint:
    """Resolve and approve the model endpoint once (raises ``EndpointRefused``)."""
    return resolve_endpoint(settings.ai.endpoint, allow_private=settings.ai.allow_private_endpoint)


def install_guard(settings: Settings, resolved: ResolvedEndpoint) -> egress.EgressGuard:
    return egress.install(settings, extra=[resolved.pair], only_allowed=True)


def ai_workers(database: Database, scope: ScopeService, settings: Settings, resolved: ResolvedEndpoint, *,
               client: Any = None) -> list[Worker]:
    client = client or OllamaClient.from_settings(settings.ai, resolver=lambda url, allow: resolved)
    adapters = PipelineAdapters(ai_client=client)
    count = settings.ai.max_concurrent_analyses
    return [Worker(database, scope, settings=settings, adapters=adapters, kinds=list(AI_JOB_KINDS),
                   limits={AI_ANALYZE: count}, worker_id=default_worker_id("ai")) for _ in range(count)]


def serve_ai(database: Database, scope: ScopeService, settings: Settings, *, drain: bool = False,
             stop: threading.Event | None = None, idle_seconds: float = 2.0, client: Any = None,
             resolved: ResolvedEndpoint | None = None, guard: Callable[..., Any] = install_guard) -> int:
    """Run analyses until stopped (or, with ``drain``, until none are due). Returns how many ran."""
    resolved = resolved or approve_endpoint(settings)
    guard(settings, resolved)
    workers = ai_workers(database, scope, settings, resolved, client=client)
    if drain:
        return workers[0].run_until_idle()
    stop = stop or threading.Event()
    ran = [0]

    def shutdown(*_: object) -> None:
        stop.set()
        for worker in workers:
            worker.shutdown()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

    def loop(worker: Worker) -> None:
        while not stop.is_set():
            try:
                busy = worker.run_once()
            except Exception:
                log.exception("AI worker loop error")
                busy = False
            ran[0] += int(busy)
            if not busy:
                stop.wait(idle_seconds)

    threads = [threading.Thread(target=loop, args=(w,), name=f"ai-worker-{i}", daemon=True) for i, w in enumerate(workers)]
    for thread in threads:
        thread.start()
    while not stop.wait(1.0):
        pass
    shutdown()
    for thread in threads:
        thread.join(timeout=settings.runtime.heartbeat_seconds + 10)
    return ran[0]
