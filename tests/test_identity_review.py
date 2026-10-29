"""Synthetic offline identity evidence. Signatures here are deliberately fake."""
import base64
import copy
import json

import pytest

from hunterqa.cli import main
from hunterqa.identity_review import MAX_BYTES, review_evidence, review_file

NOW = 1_800_000_000


def compact(header=None, claims=None, signature=b"synthetic-not-verified"):
    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")
    return ".".join((encode(json.dumps(header or {"alg": "RS256"}).encode()),
        encode(json.dumps(claims if claims is not None else {"exp": NOW + 3600, "iss": "https://issuer.example", "aud": "owned-web"}).encode()), encode(signature)))


def evidence():
    return {"schema_version": 1, "jwt_samples": [{"id": "owned-token", "token": compact(),
        "allowed_algorithms": ["RS256"], "expected_issuer": "https://issuer.example", "expected_audience": "owned-web"}],
        "oauth_clients": [{"id": "owned-client", "client_type": "public", "oidc": True,
            "issuer": "https://issuer.example", "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token", "redirect_uris": ["https://owned.example/callback"],
            "response_types": ["code"], "grant_types": ["authorization_code"],
            "pkce_required": True, "pkce_methods": ["S256"], "state_required": True,
            "nonce_required": True, "redirect_matching": "exact"}]}


def rules(report):
    return {r["rule_id"] for r in report["findings"]}


def test_quiet_fixture_is_not_authentication_proof():
    report = review_evidence(evidence(), now=NOW)
    assert not report["findings"]
    assert report["network_requests"] == 0
    assert report["observations"][0]["signature_verification"] == "not-performed"
    assert not report["observations"][1]["configuration_verified_against_provider"]
    assert report["real_world_effectiveness"] == "unverified"
    assert all(r["status"] == "partial-offline-review" for r in report["skills"])


@pytest.mark.parametrize("header,claims,signature,expected", [
    ({"alg": "none"}, {"exp": NOW + 1}, b"", {"unsigned-sample", "algorithm-policy", "issuer-policy", "audience-policy"}),
    ({"alg": "HS256"}, {}, b"fake", {"algorithm-policy", "expiry-missing"}),
    ({"alg": "RS256", "jku": "https://never-fetch.example/key", "crit": ["fixture"]}, {}, b"fake", {"key-source", "header-extension"}),
    ({"alg": "RS256"}, {"exp": NOW - 1, "nbf": NOW + 1, "iat": NOW + 1}, b"fake", {"expired-sample", "future-nbf", "future-iat", "date-order"}),
    ({"alg": "RS256"}, {"exp": True, "nbf": "tomorrow", "iat": 10 ** 400}, b"fake", {"invalid-exp", "invalid-nbf", "invalid-iat"}),
])
def test_jwt_policy_cues(header, claims, signature, expected):
    data = evidence()
    data["jwt_samples"][0]["token"] = compact(header, claims, signature)
    report = review_evidence(data, now=NOW)
    assert {"identity.jwt." + key for key in expected} <= rules(report)
    assert all(f["verification_status"] == "unverified" for f in report["findings"])


def test_jwt_audience_array_and_mixed_key_policy():
    data = evidence()
    data["jwt_samples"][0]["token"] = compact(claims={"exp": NOW + 1, "iss": "https://issuer.example", "aud": ["other", "owned-web"]})
    data["jwt_samples"][0]["allowed_algorithms"] = ["RS256", "HS256"]
    assert rules(review_evidence(data, now=NOW)) == {"identity.jwt.mixed-key-families"}


@pytest.mark.parametrize("token", ["not-a-token", "a.b.c.d.e", "A.A.A", "e30=.e30=.eA", "W10.W10.eA", "eyJhbGciOiJSUzI1NiIsImFsZyI6Im5vbmUifQ.e30.eA"])
def test_malformed_or_unsupported_token_has_no_verification_claim(token):
    data = evidence()
    data["jwt_samples"][0]["token"] = token
    report = review_evidence(data, now=NOW)
    assert rules(report) == {"identity.jwt.unsupported-token"}
    assert report["observations"][0]["format"] == "unsupported-or-malformed"


@pytest.mark.parametrize("key,value,expected", [
    ("authorization_endpoint", "http://issuer.example/authorize", "endpoint-transport"),
    ("token_endpoint", "https://secret-user:secret-pass@issuer.example/token", "endpoint-transport"),
    ("issuer", "https://[invalid", "endpoint-transport"),
    ("issuer", "https://host%20name.example", "endpoint-transport"),
    ("token_endpoint", "https://issuer.example:99999/token", "endpoint-transport"),
    ("redirect_uris", ["http://127.0.0.1/callback"], "redirect-transport"),
    ("redirect_uris", ["https://owned.example/%2a"], "redirect-matching"),
    ("redirect_matching", "prefix", "redirect-matching"),
    ("pkce_required", False, "pkce-policy"),
    ("pkce_methods", ["plain"], "pkce-policy"),
    ("pkce_methods", ["plain", "S256"], "pkce-plain"),
    ("response_types", ["token"], "front-channel-token"),
    ("grant_types", ["password"], "password-grant"),
    ("state_required", False, "csrf-binding"),
    ("nonce_required", False, "nonce-binding"),
    ("grant_types", ["client_credentials"], "public-client-credentials"),
])
def test_oauth_declaration_cues(key, value, expected):
    data = evidence()
    data["oauth_clients"][0][key] = value
    assert "identity.oauth." + expected in rules(review_evidence(data, now=NOW))


def test_report_redacts_values_and_never_fetches_or_authenticates(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("No DNS is permitted"))
    data = evidence()
    data["jwt_samples"][0]["token"] = compact({"alg": "RS256", "jku": "https://private-key-host.example"},
        {"exp": NOW + 1, "iss": "PRIVATE-ISSUER-FIXTURE", "aud": "PRIVATE-AUDIENCE-FIXTURE", "email": "private-fixture@example.test"})
    data["oauth_clients"][0]["token_endpoint"] = "https://private-user:private-password@private-endpoint.example/token"
    serialized = json.dumps(review_evidence(data, now=NOW))
    for value in (data["jwt_samples"][0]["token"], "PRIVATE-ISSUER-FIXTURE", "PRIVATE-AUDIENCE-FIXTURE", "private-fixture@example.test", "private-key-host", "private-user", "private-password", "private-endpoint"):
        assert value not in serialized


def test_absent_skill_not_assessed_and_client_credentials_not_forced_to_pkce():
    data = evidence()
    data["jwt_samples"] = []
    client = data["oauth_clients"][0]
    client.update(client_type="confidential", oidc=False, grant_types=["client_credentials"],
        response_types=[], redirect_uris=[], pkce_required=False, pkce_methods=[], state_required=False, nonce_required=False)
    assert not review_evidence(data, now=NOW)["findings"]
    assert review_evidence(data, now=NOW)["skills"][0]["status"] == "not-assessed"
    data["oauth_clients"] = []
    data["jwt_samples"] = evidence()["jwt_samples"]
    assert review_evidence(data, now=NOW)["skills"][1]["status"] == "not-assessed"


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version=True),
    lambda d: d.update(extra="PRIVATE-FIXTURE"),
    lambda d: d.update(jwt_samples=[], oauth_clients=[]),
    lambda d: d["oauth_clients"][0].update(id="owned-token"),
    lambda d: d["oauth_clients"][0].update(pkce_required="yes"),
    lambda d: d["oauth_clients"][0].update(pkce_methods=["unknown"]),
    lambda d: d["jwt_samples"][0].update(allowed_algorithms=["none"]),
    lambda d: d["jwt_samples"][0].update(token="x" * 16385),
    lambda d: d.update(jwt_samples=[copy.deepcopy(d["jwt_samples"][0])] * 11),
    lambda d: d["oauth_clients"][0].update(client_secret="PRIVATE-FIXTURE"),
])
def test_invalid_manifests_fail_without_values(mutate):
    data = evidence()
    mutate(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data, now=NOW)
    assert "PRIVATE-FIXTURE" not in str(exc.value)


def test_private_file_cli_scope_create_only_and_sarif(tmp_path, monkeypatch, capsys):
    from hunterqa.sarif_export import export_sarif
    path, output = tmp_path / "evidence.json", tmp_path / "review.json"
    data = evidence()
    data["jwt_samples"][0]["token"] = "unsupported-fixture"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PermissionError):
        review_file(path)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError):
        review_file(path, authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    args = ["identity-review", "--input", str(path), "--out", str(output), "--authorized"]
    main(args)
    report = json.loads(output.read_text())
    assert len(report["input_sha256"]) == 64
    assert export_sarif(output)["runs"][0]["results"][0]["properties"]["assessmentCase"] == "owned-token"
    with pytest.raises(FileExistsError):
        main(args)
    capsys.readouterr()
    main(["identity-review-catalog"])
    assert len(json.loads(capsys.readouterr().out)["skills"]) == 2
    path.write_bytes(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(path, authorized=True)


@pytest.mark.parametrize("raw", [b'{"schema_version":1,"schema_version":1}', b'{"schema_version":NaN}', b'{', b'{"private":"\xff"}'])
def test_bad_json_has_sanitized_error(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError, match="contents withheld"):
        review_file(path, authorized=True)


def test_published_template_requires_real_private_evidence():
    from pathlib import Path
    template = Path(__file__).resolve().parents[1] / "templates" / "HunterQA-identity-review-template.json"
    report = review_evidence(json.loads(template.read_text()), now=NOW)
    assert {"identity.jwt.unsupported-token", "identity.oauth.pkce-policy", "identity.oauth.csrf-binding", "identity.oauth.nonce-binding"} <= rules(report)


def test_scope_checks_reject_outside_input_output_and_symlink(tmp_path, monkeypatch):
    private = tmp_path / "approved"
    private.mkdir()
    path = tmp_path / "outside.json"
    path.write_text(json.dumps(evidence()), encoding="utf-8")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(private))
    with pytest.raises(ValueError):
        review_file(path, authorized=True)
    approved = private / "input.json"
    approved.write_text(json.dumps(evidence()), encoding="utf-8")
    output = tmp_path / "forbidden-output.json"
    with pytest.raises(ValueError):
        main(["identity-review", "--input", str(approved), "--out", str(output), "--authorized"])
    assert not output.exists()
    link = private / "linked.json"
    try:
        link.symlink_to(approved)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True)
