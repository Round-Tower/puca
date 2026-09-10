"""The only component that puts packets on the wire. Scope-gated by construction.

You cannot get a Sender without a Scope, and every send re-checks the target
against it. Rate-limited to the scope's rate_limit_rps.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.75, Prior: Unknown
"""
from __future__ import annotations

import time as _time
from dataclasses import dataclass

from .scope import Scope


@dataclass
class Response:
    status: int
    body: str
    elapsed: float


class Sender:
    def __init__(self, scope: Scope):
        self._scope = scope
        self._min_interval = 1.0 / max(scope.rate_limit_rps, 0.001)
        self._last = 0.0

    def _throttle(self) -> None:
        wait = self._min_interval - (_time.monotonic() - self._last)
        if wait > 0:
            _time.sleep(wait)
        self._last = _time.monotonic()

    def send(self, method: str, url: str, headers: dict[str, str] | None = None,
             body: str | None = None, timeout: float = 15.0) -> Response:
        # Fail closed: refuse anything the scope does not authorize.
        self._scope.assert_authorized(url)
        self._throttle()
        import requests  # local import so pure-logic tests need no requests

        t0 = _time.monotonic()
        r = requests.request(method, url, headers=headers or {}, data=body,
                             timeout=timeout, allow_redirects=False)
        return Response(status=r.status_code, body=r.text,
                        elapsed=_time.monotonic() - t0)
