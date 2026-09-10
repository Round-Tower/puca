from puca.ssrf import imds


def test_azure_probes_include_imds_token_endpoint():
    urls = [p.url for p in imds.azure_probes()]
    assert any("169.254.169.254" in u and "oauth2/token" in u for u in urls)
    assert all(p.headers.get("Metadata") == "true" for p in imds.azure_probes())


def test_gcp_probe_has_metadata_flavor_header():
    p = imds.gcp_probes()[0]
    assert p.headers["Metadata-Flavor"] == "Google"


def test_classify_token_leak():
    body = '{"access_token":"eyJ...","expires_in":3600}'
    assert imds.classify_response(body) == "token-leak"


def test_classify_metadata_leak():
    assert imds.classify_response('{"compute":{"name":"vm1"}}') == "metadata-leak"


def test_classify_no_leak():
    assert imds.classify_response("404 not found") == "no-leak"
    assert imds.classify_response("") == "no-leak"
