from puca.massassign import prober

# A realistic serializer field list: benign prefs + privileged fields that a
# client should never be able to write.
FIELDS = [
    "font_size", "theme", "locale", "user_interests",     # benign (must NOT probe)
    "membership_identifier", "membership_expires_at",      # entitlement -> critical
    "is_staff", "is_superuser",                            # staff -> critical
    "role",                                                # -> critical
    "stripe_customer_id",                                  # billing -> high
    "email_verified",                                      # -> high
    "user", "owner_id",                                    # FK reassignment -> high
]


# --- candidate selection -----------------------------------------------------

def test_candidates_selects_privileged_only():
    names = [f for f, _ in prober.privileged_candidates(FIELDS)]
    assert "membership_identifier" in names
    assert "is_staff" in names and "is_superuser" in names
    assert "stripe_customer_id" in names
    assert "user" in names and "owner_id" in names        # FK fields
    # benign prefs are not probed
    for benign in ("font_size", "theme", "locale"):
        assert benign not in names
    # 'user' is an FK marker but must not match an unrelated field that merely
    # starts with the token 'user' (the substring-lies lesson)
    assert "user_interests" not in names


def test_membership_and_staff_are_critical_billing_is_high():
    sev = dict(prober.privileged_candidates(FIELDS))
    assert sev["membership_identifier"] == "critical"
    assert sev["membership_expires_at"] == "critical"     # worst marker wins
    assert sev["is_staff"] == "critical"
    assert sev["role"] == "critical"
    assert sev["stripe_customer_id"] == "high"
    assert sev["owner_id"] == "high"


def test_candidates_preserve_order_and_dedupe():
    cands = prober.privileged_candidates(["is_staff", "is_staff", "font_size"])
    assert cands == [("is_staff", "critical")]


# --- non-escalating probe values --------------------------------------------

def test_probe_value_is_a_nonescalating_sentinel():
    v = str(prober.probe_value_for("membership_identifier"))
    assert "puca-probe" in v
    # never sends a value that would actually grant privilege
    assert "lifetime" not in v.lower()
    assert v != "true" and v.lower() != "true"


def test_probe_value_is_unique_per_field():
    assert prober.probe_value_for("is_staff") != prober.probe_value_for("membership_identifier")


# --- probe building ----------------------------------------------------------

def test_build_probes_one_per_privileged_field():
    probes = prober.build_probes(FIELDS)
    fields = {p.field for p in probes}
    assert "membership_identifier" in fields and "is_staff" in fields
    assert "font_size" not in fields
    for p in probes:
        assert p.payload == {p.field: p.value}
        assert p.severity in ("critical", "high")


# --- classification ----------------------------------------------------------

def test_classify_accepted_when_sentinel_persists():
    v = prober.probe_value_for("membership_identifier")
    body = '{"membership_identifier": "%s"}' % v
    assert prober.classify("membership_identifier", v, 200, body) == "accepted"


def test_classify_ignored_when_sentinel_absent():
    v = prober.probe_value_for("membership_identifier")
    # 200 but the field kept its old value -> silently dropped / read-only
    assert prober.classify("membership_identifier", v, 200,
                           '{"membership_identifier":"lifetime"}') == "ignored"


def test_classify_confirm_body_takes_precedence_over_echo():
    v = prober.probe_value_for("x_field")
    # PATCH echoed nothing; a follow-up GET confirms persistence
    assert prober.classify("x_field", v, 200, "{}",
                           confirm_body='{"x_field":"%s"}' % v) == "accepted"


def test_classify_rejected_on_readonly_error():
    v = prober.probe_value_for("membership_identifier")
    body = '{"membership_identifier":["This field is read only."]}'
    assert prober.classify("membership_identifier", v, 400, body) == "rejected"


def test_classify_writable_error_when_type_validation_names_field():
    # a bool field: our string sentinel triggers a type error that NAMES the
    # field -> the serializer treats it as writable (mass-assignable) even though
    # our sentinel type was wrong. That is still an exposure.
    v = prober.probe_value_for("is_staff")
    body = '{"is_staff":["Must be a valid boolean."]}'
    assert prober.classify("is_staff", v, 400, body) == "writable-error"


def test_classify_rejected_when_field_not_mentioned():
    v = prober.probe_value_for("is_staff")
    assert prober.classify("is_staff", v, 403, '{"detail":"forbidden"}') == "rejected"


def test_classify_other_on_5xx():
    v = prober.probe_value_for("is_staff")
    assert prober.classify("is_staff", v, 500, "boom") == "other"


# --- findings ----------------------------------------------------------------

def test_finding_for_accepted_is_A08_and_marker_severity():
    v = prober.probe_value_for("membership_identifier")
    f = prober.finding_for_accepted("membership_identifier",
                                    "/api/settings/42/", v,
                                    target="staging.example.com")
    assert f.owasp_id == "A08"
    assert f.severity == "critical"
    assert "/api/settings/42/" in f.evidence
    assert "membership_identifier" in f.title


def test_finding_writable_error_has_lower_confidence():
    v = prober.probe_value_for("is_staff")
    accepted = prober.finding_for_accepted("is_staff", "/x/", v, confidence=0.9)
    typed = prober.finding_for_accepted("is_staff", "/x/", v, confidence=0.6)
    assert typed.confidence < accepted.confidence


# --- live runner (through a fake, scope-gated Sender) ------------------------

class _EchoSender:
    """Simulates a VULNERABLE endpoint: whatever you PATCH persists and is
    returned on the confirming GET. Records every call."""
    def __init__(self):
        self.calls = []
        self._state = "{}"

    def send(self, method, url, headers=None, body=None, timeout=15.0):
        from puca.http import Response
        self.calls.append({"method": method, "url": url,
                           "headers": headers or {}, "body": body})
        if method.upper() in ("PATCH", "PUT", "POST") and body:
            self._state = body
            return Response(status=200, body=body, elapsed=0.01, headers={})
        return Response(status=200, body=self._state, elapsed=0.01, headers={})


EP = "https://staging.example.com/api/settings/42/"


def test_run_probes_only_privileged_fields():
    s = _EchoSender()
    res = prober.run(s, prober.WritableEndpoint(EP),
                     ["font_size", "membership_identifier"],
                     {"Authorization": "Bearer own"})
    patched = [c for c in s.calls if c["method"] == "PATCH"]
    assert len(patched) == 1
    assert "membership_identifier" in patched[0]["body"]
    assert "font_size" not in patched[0]["body"]
    assert any(f.owasp_id == "A08" and f.severity == "critical" for f in res.findings)


def test_run_sends_only_nonescalating_sentinels():
    s = _EchoSender()
    prober.run(s, prober.WritableEndpoint(EP), ["membership_identifier"], {})
    body = [c for c in s.calls if c["method"] == "PATCH"][0]["body"]
    assert "puca-probe" in body
    assert "lifetime" not in body.lower()


def test_run_confirms_with_a_get():
    s = _EchoSender()
    prober.run(s, prober.WritableEndpoint(EP), ["membership_identifier"], {},
               confirm=True)
    assert any(c["method"] == "GET" for c in s.calls)


def test_run_hits_the_authorized_url():
    s = _EchoSender()
    prober.run(s, prober.WritableEndpoint(EP), ["is_staff"], {})
    assert all(c["url"] == EP for c in s.calls)


# --- regression tests from the code-quality-reviewer pass --------------------

def test_classify_accepted_when_patch_echoes_but_get_omits():
    # write serializer echoes the sentinel (proves persistence); read serializer
    # on the confirm GET omits the field. Must still be 'accepted', not 'ignored'.
    v = prober.probe_value_for("membership_identifier")
    echo = '{"membership_identifier":"%s"}' % v
    thin_read = '{"font_size":14,"theme":"dark"}'
    assert prober.classify("membership_identifier", v, 200, echo,
                           confirm_body=thin_read) == "accepted"


def test_classify_named_uses_word_boundary_not_substring():
    # probed field 'role'; an unrelated 'roles' error must NOT count as naming it
    v = prober.probe_value_for("role")
    assert prober.classify("role", v, 400,
                           '{"roles":["Must be a valid list."]}') == "rejected"


def test_candidates_matches_plural_role_and_permission_fields():
    sev = dict(prober.privileged_candidates(["roles", "permissions", "balances"]))
    assert sev.get("roles") == "critical"
    assert sev.get("permissions") == "high"
    assert sev.get("balances") == "high"


def test_admin_area_is_not_a_critical_false_positive():
    # 'admin_area' (address geocoding) must not be flagged by a bare 'admin' marker
    assert prober.privileged_candidates(["admin_area"]) == []
    # but a real staff flag still is
    assert prober.privileged_candidates(["is_admin"]) == [("is_admin", "critical")]


def test_run_survives_a_send_exception_and_preserves_prior_results():
    class _FlakySender:
        def __init__(self):
            self.n = 0
        def send(self, method, url, headers=None, body=None, timeout=15.0):
            self.n += 1
            raise ConnectionError("boom")
    res = prober.run(_FlakySender(), prober.WritableEndpoint(EP),
                     ["membership_identifier", "is_staff"], {})
    # both fields recorded as 'other', errors captured, no crash, no findings
    assert [v for _, v in res.results] == ["other", "other"]
    assert len(res.errors) == 2
    assert res.findings == []


def test_writable_error_evidence_does_not_claim_accepted():
    v = prober.probe_value_for("is_staff")
    f = prober.finding_for_accepted("is_staff", "/x/", v, kind="writable-error")
    assert "was accepted" not in f.evidence
    assert "writable" in f.evidence.lower()
