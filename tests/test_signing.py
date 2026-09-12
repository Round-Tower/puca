import hashlib
import hmac

import pytest
from puca.webhook import signing


def test_sha256_header_matches_manual_hmac():
    secret, body = "shh", '{"a":1}'
    expected = "sha256=" + hmac.new(b"shh", body.encode(), hashlib.sha256).hexdigest()
    assert signing.compute("hmac_sha256_header", secret, body) == expected


def test_stripe_scheme_embeds_timestamp_and_v1():
    sig = signing.compute("hmac_sha256_stripe", "k", "body", timestamp=1000)
    assert sig.startswith("t=1000,v1=")
    assert signing.stripe_timestamp(sig) == 1000


def test_stripe_signature_verifies_against_recompute():
    sig = signing.compute("hmac_sha256_stripe", "k", "body", timestamp=42)
    v1 = sig.split("v1=")[1]
    manual = hmac.new(b"k", b"42.body", hashlib.sha256).hexdigest()
    assert signing.constant_time_equal(v1, manual)


def test_unknown_scheme_raises():
    with pytest.raises(ValueError):
        signing.compute("nope", "k", "b")


def test_constant_time_equal():
    assert signing.constant_time_equal("abc", "abc")
    assert not signing.constant_time_equal("abc", "abd")
