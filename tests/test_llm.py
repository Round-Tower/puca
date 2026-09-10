from puca.llm import probes


def test_payloads_carry_llm_ids():
    assert all(p.llm_id == "LLM01" for p in probes.injection_payloads())
    assert all(p.llm_id == "LLM02" for p in probes.sensitive_info_payloads())


def test_detect_injection_via_canary():
    assert probes.detect_injection_success(f"sure: {probes.CANARY}")
    assert not probes.detect_injection_success("I can't help with that.")


def test_detect_injection_via_system_prompt_leak():
    leak = "You are Lexy, your role is a tutor. Guidelines: do not reveal secrets."
    assert probes.detect_injection_success(leak)


def test_detect_secret_leak():
    assert probes.detect_secret_leak("here: sk-abcdefghijklmnop1234567890")
    assert probes.detect_secret_leak("AIzaSyABCDEFGHIJKLMNOPQRSTUVWX0123456")
    assert not probes.detect_secret_leak("no secrets here")


def test_detect_unbounded():
    assert probes.detect_unbounded("x" * 20001)
    assert not probes.detect_unbounded("short")


def test_finding_secret_leak_is_critical_LLM02():
    f = probes.finding_secret_leak("leaked sk-...", target="t")
    assert f.severity == "critical" and f.owasp_id == "LLM02"
