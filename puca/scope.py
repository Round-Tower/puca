"""Engagement scope + authorization gate.

The single safety invariant of Puca: no dynamic test runs against a target
unless a scope file explicitly authorizes it. Every network-touching entry
point calls Scope.assert_authorized(target) first.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.8, Prior: Unknown
Why: this is the white-hat line. It must fail closed on any doubt.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any


class ScopeError(Exception):
    """Raised when a target is not authorized. Fail closed: refuse the test."""


@dataclass
class Scope:
    engagement: str
    authorized_by: str
    authorization: bool
    start: _dt.date | None
    end: _dt.date | None
    rate_limit_rps: float
    in_scope_hosts: set[str] = field(default_factory=set)
    out_of_scope: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        def _date(v: Any) -> _dt.date | None:
            if v in (None, ""):
                return None
            if isinstance(v, _dt.date):
                return v
            return _dt.date.fromisoformat(str(v))

        hosts = {
            str(e["host"]).strip().lower()
            for e in (data.get("in_scope") or [])
            if isinstance(e, dict) and e.get("host")
        }
        window = data.get("window") or {}
        return cls(
            engagement=str(data.get("engagement", "")),
            authorized_by=str(data.get("authorized_by", "")),
            authorization=bool(data.get("authorization", False)),
            start=_date(window.get("start")),
            end=_date(window.get("end")),
            rate_limit_rps=float(data.get("rate_limit_rps", 1)),
            in_scope_hosts=hosts,
            out_of_scope=list(data.get("out_of_scope") or []),
            raw=data,
        )

    @classmethod
    def load(cls, path: str) -> "Scope":
        import yaml  # local import so tests of pure logic need no yaml

        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    @staticmethod
    def _host_of(target: str) -> str:
        from urllib.parse import urlparse

        t = target.strip().lower()
        if "://" not in t:
            t = "//" + t
        host = urlparse(t).hostname or ""
        return host

    def is_authorized(self, target: str, today: _dt.date | None = None) -> bool:
        try:
            self.assert_authorized(target, today=today)
            return True
        except ScopeError:
            return False

    def assert_authorized(self, target: str, today: _dt.date | None = None) -> None:
        """Fail closed. Raise ScopeError unless every condition passes."""
        if not self.authorization:
            raise ScopeError("scope.authorization is not true — refusing to test")
        host = self._host_of(target)
        if not host:
            raise ScopeError(f"could not parse a host from target {target!r}")
        if host not in self.in_scope_hosts:
            raise ScopeError(
                f"host {host!r} is not in scope (in_scope={sorted(self.in_scope_hosts)})"
            )
        today = today or _dt.date.today()
        if self.start and today < self.start:
            raise ScopeError(f"engagement window has not started (starts {self.start})")
        if self.end and today > self.end:
            raise ScopeError(f"engagement window has ended ({self.end})")
