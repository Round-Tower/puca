import datetime as dt
import pytest
from puca.scope import Scope, ScopeError
from puca.http import Sender

SCOPE = Scope.from_dict({
    "authorization": True,
    "window": {"start": "2026-09-01", "end": "2026-12-31"},
    "rate_limit_rps": 1000,
    "in_scope": [{"host": "staging.example.com"}],
})


class _FakeResp:
    def __init__(self):
        self.status_code = 200
        self.text = "ok"
        self.headers = {"Strict-Transport-Security": "max-age=1", "Server": "x"}
        self.elapsed = dt.timedelta(seconds=0.01)


def test_sender_refuses_out_of_scope(monkeypatch):
    s = Sender(SCOPE)
    with pytest.raises(ScopeError):
        s.send("GET", "https://example.com/")  # prod not in scope


def test_sender_returns_status_and_headers(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "request", lambda *a, **k: _FakeResp())
    s = Sender(SCOPE)
    r = s.send("GET", "https://staging.example.com/")
    assert r.status == 200
    assert r.headers["Strict-Transport-Security"] == "max-age=1"
    assert r.elapsed == pytest.approx(0.01)
