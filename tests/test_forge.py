from puca.webhook import forge, signing


def test_unsigned_has_no_signature_header():
    r = forge.unsigned("https://h/w", '{"x":1}', {"X-Sig": "should-be-dropped"})
    # only explicit extra headers are merged; unsigned adds none of its own sig
    assert "X-Sig" in r.headers  # caller-supplied passthrough
    assert r.label == "forge:unsigned"
    assert r.method == "POST"


def test_wrong_signature_is_zeroed():
    r = forge.wrong_signature("https://h/w", "b", "X-Sig")
    assert r.headers["X-Sig"] == "sha256=" + "0" * 64


def test_tampered_body_keeps_signature_changes_body():
    r = forge.tampered_body("https://h/w", "orig", "X-Sig", "sha256=abc", '{"evil":1}')
    assert r.body == '{"evil":1}'
    assert r.headers["X-Sig"] == "sha256=abc"


def test_valid_if_secret_known_roundtrips():
    body = '{"ok":1}'
    r = forge.valid_if_secret_known("https://h/w", body, "X-Sig",
                                    "hmac_sha256_header", "secret")
    assert r.headers["X-Sig"] == signing.compute("hmac_sha256_header", "secret", body)
