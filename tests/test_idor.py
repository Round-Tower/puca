from puca.access import idor

A = idor.Identity("alice", {"Authorization": "Bearer a"})
B = idor.Identity("bob", {"Authorization": "Bearer b"})
R_A = idor.Resource("/api/sessions/1/", owner="alice", owner_marker="alice@x.com")
R_B = idor.Resource("/api/sessions/2/", owner="bob", owner_marker="bob@x.com")


def test_matrix_is_cross_account_only():
    probes = idor.build_matrix([A, B], [R_A, R_B])
    labels = {(p.requester, p.resource.owner) for p in probes}
    assert ("alice", "bob") in labels and ("bob", "alice") in labels
    assert ("alice", "alice") not in labels  # own resources skipped
    assert len(probes) == 2


def test_classify_idor_leak():
    # alice fetches bob's resource, gets 200 with bob's marker -> leak
    assert idor.classify("alice", R_B, 200, '{"user":"bob@x.com"}') == "idor-leak"


def test_classify_blocked():
    assert idor.classify("alice", R_B, 403, "") == "blocked"
    assert idor.classify("alice", R_B, 404, "") == "blocked"


def test_classify_filtered_ok():
    # 200 but no owner marker -> returned own/empty view, not a leak
    assert idor.classify("alice", R_B, 200, '{"user":"alice@x.com"}') == "filtered-ok"


def test_own_access_labelled_own():
    assert idor.classify("bob", R_B, 200, "bob@x.com") == "own"


def test_finding_for_leak_is_high_A01():
    f = idor.finding_for_leak("alice", R_B, target="staging.example.com")
    assert f.severity == "high" and f.owasp_id == "A01"
