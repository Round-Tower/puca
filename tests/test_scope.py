import datetime as dt
import pytest
from puca.scope import Scope, ScopeError

BASE = {
    "engagement": "test",
    "authorized_by": "Kev",
    "authorization": True,
    "window": {"start": "2026-09-01", "end": "2026-09-30"},
    "rate_limit_rps": 5,
    "in_scope": [{"host": "staging.example.com", "base_url": "https://staging.example.com"}],
}
TODAY = dt.date(2026, 9, 10)


def s(**over):
    d = {**BASE, **over}
    return Scope.from_dict(d)


def test_authorized_in_scope():
    assert s().is_authorized("https://staging.example.com/api/webhooks/x/", today=TODAY)


def test_refuses_when_authorization_false():
    with pytest.raises(ScopeError):
        s(authorization=False).assert_authorized("https://staging.example.com/", today=TODAY)


def test_refuses_out_of_scope_host():
    assert not s().is_authorized("https://example.com/", today=TODAY)
    assert not s().is_authorized("https://evil.example.com/", today=TODAY)


def test_refuses_before_window():
    with pytest.raises(ScopeError):
        s().assert_authorized("https://staging.example.com/", today=dt.date(2026, 8, 1))


def test_refuses_after_window():
    with pytest.raises(ScopeError):
        s().assert_authorized("https://staging.example.com/", today=dt.date(2026, 10, 1))


def test_bare_host_target_parses():
    assert s().is_authorized("staging.example.com", today=TODAY)


def test_unparseable_target_refused():
    with pytest.raises(ScopeError):
        s().assert_authorized("://", today=TODAY)
