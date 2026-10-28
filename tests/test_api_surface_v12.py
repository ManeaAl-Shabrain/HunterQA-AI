import json

import pytest

from hunterqa.api_surface_v12 import inspect_openapi


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    profile = tmp_path / "scope.json"
    profile.write_text(json.dumps({
        "platform": "local-lab", "program": "Owned API fixture",
        "authorization_reference": "Written fixture approval for owned API",
        "acknowledged_authorization": True, "allowed_hosts": ["app.example.test"],
    }))
    return tmp_path, profile


def spec(root, data):
    folder, _ = root
    path = folder / "openapi.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_openapi_discovery_is_offline_and_reports_unverified_candidates(root):
    raw = {
        "openapi": "3.1.0", "info": {"title": "Owned example", "version": "1"},
        "servers": [{"url": "https://not-a-target.example.invalid"}],
        "paths": {
            "/v1/users/{userId}": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "patch": {"requestBody": {"content": {"application/json": {}}},
                          "responses": {"200": {"description": "ok"}}},
            },
            "/v1/admin/permissions": {
                "post": {"security": [], "responses": {"204": {"description": "ok"}}},
            },
        },
    }
    result = inspect_openapi(spec(root, raw), root[1], authorized=True)
    assert result["summary"]["operations"] == 3
    assert len(result["operations"]) == 3
    assert result["summary"]["confirmed_zero_days"] == 0
    ids = {x["rule_id"] for x in result["review_candidates"]}
    assert "api.object-access-review" in ids
    assert "api.auth-declaration-review" in ids
    assert "api.public-write-review" in ids
    assert "api.business-logic-review" in ids
    assert result["servers"][0]["scope_status"] == "unverified_or_out_of_scope"
    assert all(x["confirmed"] is False for x in result["review_candidates"])


def test_security_inherited_and_operation_override(root):
    p = spec(root, {
        "openapi": "3.0.3", "security": [{"ApiKeyAuth": []}],
        "paths": {"/secure": {"get": {}},
                  "/public": {"get": {"security": []}},
                  "/local": {"get": {"security": [{"Bearer": []}]}}},
    })
    result = inspect_openapi(p, root[1], authorized=True)
    lookup = {x["path_template"]: x["auth_declaration"] for x in result["operations"]}
    assert lookup["/secure"] == "declared_inherited"
    assert lookup["/public"] == "explicitly_public"
    assert lookup["/local"] == "declared"


def test_no_live_network_or_reference_resolution(root, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *args, **kw: (_ for _ in ()).throw(AssertionError("Network attempted")))
    p = spec(root, {"openapi": "3.1.0", "paths": {
        "/account": {"post": {"$ref": "https://outside.example.test/schema",
                               "requestBody": {"$ref": "https://outside.example.test/body"}}}
    }})
    result = inspect_openapi(p, root[1], authorized=True)
    assert result["summary"]["operations"] == 1


def test_authorization_required(root):
    p = spec(root, {"openapi": "3.1.0", "paths": {}})
    with pytest.raises(PermissionError):
        inspect_openapi(p, root[1])


@pytest.mark.parametrize("doc", [
    {"swagger": "2.0", "paths": {}},
    {"openapi": "3.2.0", "paths": {}},
    {"openapi": "3.1.0", "paths": []},
    {"openapi": "3.1.0", "paths": {"/": {"get": {}}}, "servers": "bad"},
])
def test_invalid_documents_fail_closed(root, doc):
    with pytest.raises(ValueError):
        inspect_openapi(spec(root, doc), root[1], authorized=True)


def test_too_many_paths_bounded(root):
    doc = {"openapi": "3.1.0", "paths": {f"/p/{i}": {"get": {}} for i in range(251)}}
    with pytest.raises(ValueError, match="250"):
        inspect_openapi(spec(root, doc), root[1], authorized=True)


def test_duplicate_json_keys_rejected(root):
    p = root[0] / "duplicate.json"
    p.write_text('{"openapi":"3.1.0","paths":{},"paths":{"/admin":{"get":{}}}}')
    with pytest.raises(ValueError, match="Duplicate"):
        inspect_openapi(p, root[1], authorized=True)


def test_file_outside_approved_local_root_fails(root, tmp_path, monkeypatch):
    p = spec(root, {"openapi": "3.1.0", "paths": {}})
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path / "not-a-root"))
    with pytest.raises((ValueError, FileNotFoundError)):
        inspect_openapi(p, root[1], authorized=True)


def test_symlinked_spec_fails_closed(root):
    p = spec(root, {"openapi": "3.1.0", "paths": {}})
    link = root[0] / "link.json"
    link.symlink_to(p)
    with pytest.raises(ValueError, match="Symlink"):
        inspect_openapi(link, root[1], authorized=True)


def test_invalid_security_declaration_is_not_marked_safe(root):
    p = spec(root, {"openapi": "3.1.0", "security": "broken",
                    "paths": {"/payments": {"post": {}}}})
    result = inspect_openapi(p, root[1], authorized=True)
    assert result["operations"][0]["auth_declaration"] == "invalid"
    assert result["review_candidates"][0]["confirmed"] is False


def test_no_sensitive_server_secret_in_inventory(root):
    p = spec(root, {"openapi": "3.1.0", "paths": {}, "servers": [
        {"url": "https://example.test/?api_key=do-not-store-in-full"},
    ]})
    result = inspect_openapi(p, root[1], authorized=True)
    assert result["summary"]["operations"] == 0
    assert "do-not-store-in-full" not in json.dumps(result)
    assert result["claims"]["confirmed_vulnerabilities"] == 0
