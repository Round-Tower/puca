import pytest
from puca.webhook import forge, replay, signing


def _captured():
    body = "body"
    sig = signing.compute("hmac_sha256_stripe", "k", body, timestamp=1_000_000)
    return forge.Request(url="https://h/w", headers={"X-Sig": sig}, body=body)


def test_replay_verbatim_preserves_everything():
    c = _captured()
    r = replay.replay(c)
    assert r.headers == c.headers and r.body == c.body
    assert r.label == "replay:verbatim"


def test_stale_timestamp_visible_only_when_no_secret():
    c = _captured()
    r = replay.with_stale_timestamp(c, "X-Sig", age_seconds=600)
    assert signing.stripe_timestamp(r.headers["X-Sig"]) == 1_000_000 - 600
    # v1 unchanged because we didn't recompute
    assert r.headers["X-Sig"].split("v1=")[1] == c.headers["X-Sig"].split("v1=")[1]


def test_stale_timestamp_recomputes_with_secret():
    c = _captured()
    r = replay.with_stale_timestamp(c, "X-Sig", age_seconds=600, secret="k")
    expected = signing.compute("hmac_sha256_stripe", "k", c.body, timestamp=1_000_000 - 600)
    assert r.headers["X-Sig"] == expected


def test_stale_requires_stripe_timestamp():
    c = forge.Request(url="https://h/w", headers={"X-Sig": "sha256=abc"}, body="b")
    with pytest.raises(ValueError):
        replay.with_stale_timestamp(c, "X-Sig", age_seconds=1)


def test_duplicate_event_count_and_labels():
    rs = replay.duplicate_event(_captured(), times=3)
    assert len(rs) == 3
    assert rs[0].label == "replay:idempotency-1/3"
