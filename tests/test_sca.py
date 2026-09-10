from puca.sca import audit

PIP = {"dependencies": [
    {"name": "django", "version": "6.0.7",
     "vulns": [{"id": "PYSEC-2026-1", "description": "DoS", "fix_versions": ["6.0.8"]}]},
    {"name": "leftpad", "version": "1.0",
     "vulns": [{"id": "CVE-2026-9", "description": "RCE", "fix_versions": []}]},
    {"name": "clean", "version": "1.0", "vulns": []},
]}
NPM = {"vulnerabilities": {
    "lodash": {"severity": "critical", "via": [{"title": "Prototype pollution"}], "fixAvailable": True},
    "minor": {"severity": "moderate", "via": ["x"], "fixAvailable": {"name": "minor", "version": "2.0"}},
}}


def test_pip_audit_maps_to_A06_and_counts_only_vulnerable():
    fs = audit.parse_pip_audit(PIP)
    assert len(fs) == 2  # 'clean' has no vulns
    assert all(f.owasp_id == "A06" for f in fs)


def test_pip_audit_no_fix_is_high():
    fs = {f.title.split()[0]: f for f in audit.parse_pip_audit(PIP)}
    assert fs["leftpad"].severity == "high"   # no fix_versions
    assert fs["django"].severity == "medium"  # fix available


def test_npm_severity_mapping():
    fs = {f.title.split(":")[0]: f for f in audit.parse_npm_audit(NPM)}
    assert fs["lodash"].severity == "critical"
    assert fs["minor"].severity == "medium"   # moderate -> medium


def test_accepts_json_string():
    import json
    assert len(audit.parse_pip_audit(json.dumps(PIP))) == 2
