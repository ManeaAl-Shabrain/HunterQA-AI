"""Owned decoded configuration fixtures, not installed applications or devices."""
import copy
import hashlib
import json
import plistlib
import traceback

import pytest

from hunterqa.cli import main
from hunterqa.mobile_review import AREAS, MAX_BYTES, review_evidence, review_file

QUIET = {
    "storage": {"sensitive_data_protected": True, "secrets_in_logs": False, "backup_policy_reviewed": True},
    "transport": {"tls_validation_enforced": True, "cleartext_permitted": False, "pinning_policy_reviewed": True},
    "webview": {"untrusted_content_allowed": False, "native_bridge_restricted": True, "file_access_restricted": True},
    "authentication": {"biometric_authentication_used": True, "biometric_crypto_binding": True, "session_revocation_reviewed": True, "local_authorization_reviewed": True},
    "links": {"input_validation_reviewed": True, "ownership_association_verified": True, "sensitive_action_requires_auth": True},
    "ipc": {"exported_surface_reviewed": True, "sender_authentication_reviewed": True, "least_privilege_reviewed": True},
    "build": {"production_debug_disabled": True, "release_signing_verified": True, "dependency_patch_reviewed": True},
}
CHANGES = {"storage": ("secrets_in_logs", True), "transport": ("tls_validation_enforced", False),
    "webview": ("file_access_restricted", False), "authentication": ("biometric_crypto_binding", False),
    "links": ("sensitive_action_requires_auth", False), "ipc": ("sender_authentication_reviewed", False),
    "build": ("production_debug_disabled", False)}


def evidence(platform="android", area="storage", **updates):
    return {"schema_version": 1, "records": [{"id": "owned-one", "platform": platform, "area": area,
        "observations": {f: updates.get(f) for f in AREAS[area]}}]}


def rules(report):
    return {f["rule_id"] for f in report["findings"]}


def native(tmp_path, monkeypatch, mode, raw):
    path = tmp_path / "source.xml"
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_file(path, authorized=True, mode=mode)


def manifest(attributes="", children="", permissions=""):
    return '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="PRIVATE-PACKAGE">' + permissions + '<application android:name="PRIVATE-CLASS" ' + attributes + '>' + children + '</application></manifest>'


@pytest.mark.parametrize("platform", ("android", "ios"))
@pytest.mark.parametrize("area", AREAS)
def test_positive_and_negative_controls_for_all_fourteen_views(platform, area):
    baseline = review_evidence(evidence(platform, area, **QUIET[area]))
    assert not baseline["findings"]
    assert baseline["platforms"][platform]["status"] == "partial-offline-review"
    assert baseline["network_requests"] == baseline["device_actions_executed"] == baseline["external_tools_executed"] == 0
    assert not baseline["runtime_enforcement_verified"] and not baseline["signature_verified"]
    field, value = CHANGES[area]
    report = review_evidence(evidence(platform, area, **{**QUIET[area], field: value}))
    assert rules(report) == {"mobile-review." + platform + "." + area + "." + field.replace("_", "-")}
    assert report["real_world_effectiveness"] == "unverified" and not report["all_skills_automated"]


def test_contextual_webview_and_biometric_checks():
    data = evidence(area="webview", untrusted_content_allowed=True, native_bridge_restricted=False)
    assert rules(review_evidence(data)) == {"mobile-review.android.webview.untrusted-content-allowed", "mobile-review.android.webview.native-bridge-restricted"}
    assert not review_evidence(evidence(area="authentication", biometric_authentication_used=False, biometric_crypto_binding=False))["findings"]
    report = review_evidence(evidence())
    assert report["platforms"]["android"]["status"] == "insufficient-evidence"
    assert report["platforms"]["ios"]["status"] == "not-assessed"


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version=True), lambda d: d.update(package="PRIVATE-FIXTURE"),
    lambda d: d.update(records=[]), lambda d: d["records"][0].update(platform="other"),
    lambda d: d["records"][0].update(area="execute-device-command"),
    lambda d: d["records"][0].update(secret="PRIVATE-FIXTURE"),
    lambda d: d["records"][0]["observations"].update(sensitive_data_protected=1),
    lambda d: d["records"][0]["observations"].update(extra="PRIVATE-FIXTURE"),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_invalid_normalized_schema_withholds_values(mutate):
    data = evidence()
    mutate(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE-FIXTURE" not in str(exc.value)


def test_record_and_candidate_bounds(monkeypatch):
    import hunterqa.mobile_review as module
    row = evidence(secrets_in_logs=True, sensitive_data_protected=False)["records"][0]
    with pytest.raises(ValueError):
        review_evidence({"schema_version": 1, "records": [{**copy.deepcopy(row), "id": "case-" + str(i)} for i in range(11)]})
    monkeypatch.setattr(module, "MAX_FINDINGS", 1)
    report = review_evidence({"schema_version": 1, "records": [row]})
    assert report["truncated"] and report["candidates_not_retained"] == 1


@pytest.mark.parametrize("attribute,key", [
    ("debuggable", "debuggable"), ("allowBackup", "allowbackup"),
    ("usesCleartextTraffic", "usescleartexttraffic"), ("testOnly", "testonly"),
    ("requestLegacyExternalStorage", "requestlegacyexternalstorage"),
])
def test_android_manifest_explicit_boolean_controls(tmp_path, monkeypatch, attribute, key):
    _, positive = native(tmp_path, monkeypatch, "android-manifest", manifest('android:' + attribute + '="true"'))
    assert rules(positive) == {"mobile-review.android.manifest." + key}
    _, negative = native(tmp_path, monkeypatch, "android-manifest", manifest('android:' + attribute + '="false"'))
    assert not negative["findings"]
    assert "PRIVATE" not in json.dumps(positive)


def test_android_missing_defaults_and_resource_paths_remain_unknown(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "android-manifest", manifest('android:debuggable="@bool/PRIVATE" android:networkSecurityConfig="@xml/PRIVATE" android:dataExtractionRules="@xml/PRIVATE"'))
    assert not report["findings"]
    assert report["records"][0]["status"] == "insufficient-evidence"
    assert report["source_review"]["network_config_reference_present"]
    assert report["source_review"]["backup_resource_reference_present"]
    assert report["referenced_files_opened"] == 0 and "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("kind", ("activity", "activity-alias", "service", "receiver", "provider"))
def test_android_export_is_surface_review_not_permission_proof(tmp_path, monkeypatch, kind):
    child = '<' + kind + ' android:name="PRIVATE-COMPONENT" android:permission="PRIVATE-PERMISSION" android:exported="true"/>'
    _, report = native(tmp_path, monkeypatch, "android-manifest", manifest(children=child))
    assert rules(report) == {"mobile-review.android.manifest.exported-component"}
    assert report["findings"][0]["severity"] == "INFO"
    assert "PRIVATE" not in json.dumps(report)
    _, negative = native(tmp_path, monkeypatch, "android-manifest", manifest(children=child.replace('exported="true"', 'exported="false"')))
    assert not negative["findings"]


def test_android_link_and_missing_export_contract_do_not_infer_runtime_exposure(tmp_path, monkeypatch):
    child = '<activity android:name="PRIVATE"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="PRIVATE-SCHEME" android:host="PRIVATE-HOST"/></intent-filter></activity>'
    _, report = native(tmp_path, monkeypatch, "android-manifest", manifest(children=child))
    assert rules(report) == {"mobile-review.android.manifest.unspecified-export", "mobile-review.android.manifest.link-handler"}
    assert "PRIVATE" not in json.dumps(report)
    assert not report["runtime_enforcement_verified"]


@pytest.mark.parametrize("level,flagged", [("normal", True), ("dangerous", True), ("signature", False)])
def test_android_permission_class_is_a_contextual_review(tmp_path, monkeypatch, level, flagged):
    _, report = native(tmp_path, monkeypatch, "android-manifest", manifest(permissions='<permission android:name="PRIVATE" android:protectionLevel="' + level + '"/>'))
    assert bool(report["findings"]) is flagged


def test_android_network_explicit_trust_and_pin_overrides(tmp_path, monkeypatch):
    config = '<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user" overridePins="true"/></trust-anchors></base-config></network-security-config>'
    _, report = native(tmp_path, monkeypatch, "android-network-security", config)
    assert rules(report) == {"mobile-review.android.network.cleartext", "mobile-review.android.network.user-ca", "mobile-review.android.network.pin-override"}
    config = config.replace('="true"', '="false"').replace('src="user"', 'src="system"')
    _, negative = native(tmp_path, monkeypatch, "android-network-security", config)
    assert not negative["findings"]


def test_android_debug_only_trust_is_not_global_release_trust(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "android-network-security", '<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides></network-security-config>')
    assert report["records"][0]["debug_only_context"]
    assert report["findings"][0]["severity"] == "INFO"


@pytest.mark.parametrize("expiration,flagged", [("2000-01-01", True), ("2099-01-01", False)])
def test_android_pin_expiration_without_exporting_domains_or_pins(tmp_path, monkeypatch, expiration, flagged):
    config = '<network-security-config><domain-config cleartextTrafficPermitted="false"><domain>PRIVATE-DOMAIN</domain><pin-set expiration="' + expiration + '"><pin digest="SHA-256">PRIVATE-PIN</pin></pin-set></domain-config></network-security-config>'
    _, report = native(tmp_path, monkeypatch, "android-network-security", config)
    assert bool(report["findings"]) is flagged
    assert "PRIVATE" not in json.dumps(report)


def test_android_nested_network_policies_are_not_collapsed_to_effective_policy(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "android-network-security", '<network-security-config><domain-config cleartextTrafficPermitted="false"><domain>PRIVATE-ONE</domain><domain-config cleartextTrafficPermitted="true"><domain>PRIVATE-TWO</domain></domain-config></domain-config></network-security-config>')
    assert len(report["records"]) == 2 and len(report["findings"]) == 1
    assert not report["runtime_enforcement_verified"]


@pytest.mark.parametrize("key", ("NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"))
def test_ios_ats_explicit_boolean_controls(tmp_path, monkeypatch, key):
    _, positive = native(tmp_path, monkeypatch, "ios-info", plistlib.dumps({"CFBundleIdentifier": "PRIVATE-ID", "NSAppTransportSecurity": {key: True}}))
    assert rules(positive) == {"mobile-review.ios.ats." + key.lower()}
    assert "PRIVATE-ID" not in json.dumps(positive)
    _, negative = native(tmp_path, monkeypatch, "ios-info", plistlib.dumps({"NSAppTransportSecurity": {key: False}}))
    assert not negative["findings"]


def test_ios_ats_precedence_is_not_assumed_to_disable_transport_security(tmp_path, monkeypatch):
    _, report = native(tmp_path, monkeypatch, "ios-info", plistlib.dumps({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True, "NSAllowsArbitraryLoadsInWebContent": False}}))
    assert len(report["findings"]) == 1
    assert "OS/key precedence" in report["findings"][0]["message"]
    assert not report["runtime_enforcement_verified"]


def test_ios_domain_url_and_sharing_declarations_withhold_source_values(tmp_path, monkeypatch):
    data = {"PRIVATE-SECRET-KEY": "PRIVATE-TOKEN", "NSAppTransportSecurity": {"NSExceptionDomains": {"PRIVATE-DOMAIN": {
        "NSExceptionAllowsInsecureHTTPLoads": True, "NSExceptionRequiresForwardSecrecy": False, "NSExceptionMinimumTLSVersion": "TLSv1.0"}}},
        "CFBundleURLTypes": [{"CFBundleURLName": "PRIVATE-NAME", "CFBundleURLSchemes": ["PRIVATE-SCHEME"]}],
        "UIFileSharingEnabled": True, "LSSupportsOpeningDocumentsInPlace": True}
    _, report = native(tmp_path, monkeypatch, "ios-info", plistlib.dumps(data))
    assert len(report["findings"]) == 6
    assert "PRIVATE" not in json.dumps(report)


def test_ios_entitlements_are_not_signed_capability_proof(tmp_path, monkeypatch):
    data = {"get-task-allow": True, "keychain-access-groups": ["PRIVATE-A", "PRIVATE-B"],
        "com.apple.security.application-groups": ["PRIVATE-CONTAINER"], "com.apple.developer.associated-domains": ["applinks:PRIVATE-DOMAIN"],
        "com.apple.private.PRIVATE-CAPABILITY": True}
    _, report = native(tmp_path, monkeypatch, "ios-entitlements", plistlib.dumps(data))
    assert len(report["findings"]) == 5 and not report["signature_verified"]
    assert "PRIVATE" not in json.dumps(report)
    _, negative = native(tmp_path, monkeypatch, "ios-entitlements", plistlib.dumps({"get-task-allow": False, "keychain-access-groups": ["PRIVATE-ONE"]}))
    assert not negative["findings"]


@pytest.mark.parametrize("mode,raw", [
    ("android-manifest", b'<!DOCTYPE manifest [<!ENTITY xxe SYSTEM "file:///PRIVATE-NEVER-OPEN">]><manifest><application>&xxe;</application></manifest>'),
    ("android-manifest", b'<!DOCTYPE manifest SYSTEM "https://PRIVATE-NEVER-FETCH"><manifest><application/></manifest>'),
    ("ios-info", b'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "https://PRIVATE-NEVER-FETCH">]><plist version="1.0"><dict><key>PRIVATE</key><string>&xxe;</string></dict></plist>'),
    ("ios-info", b'<!DOCTYPE plist [<!ENTITY unused "PRIVATE">]><plist version="1.0"><dict/></plist>'),
    ("android-manifest", b'<manifest xmlns:xi="http://www.w3.org/2001/XInclude"><application/><xi:include href="file:///PRIVATE"/></manifest>'),
    ("ios-info", b'bplist00PRIVATE-BINARY'),
    ("android-manifest", b'PK\x03\x04PRIVATE-APK'),
    ("android-manifest", b'\xffPRIVATE'),
])
def test_unsafe_or_unsupported_xml_formats_fail_without_source_contents(tmp_path, monkeypatch, mode, raw):
    path = tmp_path / "bad.xml"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path, authorized=True, mode=mode)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


@pytest.mark.parametrize("raw", [
    '<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict/><key>NSAppTransportSecurity</key><dict/></dict></plist>',
    '<plist version="1.0"><dict><key>PRIVATE</key><integer>PRIVATE-INVALID</integer></dict></plist>',
    '<plist version="1.0"><dict><key>PRIVATE</key><real>PRIVATE-INVALID</real></dict></plist>',
    '<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><string>PRIVATE-NOT-BOOLEAN</string></dict></dict></plist>',
    '<plist version="1.0"><dict><key>PRIVATE-DANGLING</key></dict></plist>',
])
def test_plist_ambiguity_and_conversion_errors_do_not_leak_values(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.xml"
    path.write_text(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path, authorized=True, mode="ios-info")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_network_date_errors_suppress_original_value_in_tracebacks(tmp_path, monkeypatch):
    path = tmp_path / "bad.xml"
    path.write_text('<network-security-config><base-config><pin-set expiration="PRIVATE-INVALID"/></base-config></network-security-config>')
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path, authorized=True, mode="android-network-security")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_xml_node_and_depth_bounds(tmp_path, monkeypatch):
    import hunterqa.mobile_review as module
    path = tmp_path / "bounded.xml"
    path.write_text(manifest(children='<activity><intent-filter/></activity>'))
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    monkeypatch.setattr(module, "MAX_XML_NODES", 3)
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode="android-manifest")
    monkeypatch.setattr(module, "MAX_XML_NODES", 5000)
    monkeypatch.setattr(module, "MAX_XML_DEPTH", 2)
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode="android-manifest")


def test_no_device_network_or_tool_execution_including_apple_dtd(tmp_path, monkeypatch):
    import socket
    import subprocess
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("No DNS"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("No external tools"))
    _, report = native(tmp_path, monkeypatch, "ios-info", plistlib.dumps({"CFBundleIdentifier": "PRIVATE-ID"}))
    assert not report["findings"] and report["platforms"]["ios"]["status"] == "insufficient-evidence"
    assert report["device_actions_executed"] == report["referenced_files_opened"] == report["network_requests"] == 0
    _, utf16 = native(tmp_path, monkeypatch, "android-manifest", manifest('android:debuggable="true"').encode("utf-16"))
    assert len(utf16["findings"]) == 1


MODE_INPUTS = [
    ("normalized", json.dumps(evidence(secrets_in_logs=True)).encode()),
    ("android-manifest", manifest('android:debuggable="true"').encode()),
    ("android-network-security", b'<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'),
    ("ios-info", plistlib.dumps({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})),
    ("ios-entitlements", plistlib.dumps({"get-task-allow": True})),
]


@pytest.mark.parametrize("mode,raw", MODE_INPUTS)
def test_cli_authorization_roots_private_receipts_nonoverwrite_and_sarif(tmp_path, monkeypatch, capsys, mode, raw):
    from hunterqa.sarif_export import export_sarif
    path, output = tmp_path / "input", tmp_path / "report.json"
    path.write_bytes(raw)
    with pytest.raises(PermissionError):
        review_file(path, mode=mode)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode=mode)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    args = ["mobile-review" if mode == "normalized" else "mobile-config-review", "--input", str(path), "--out", str(output), "--authorized"]
    if mode != "normalized":
        args += ["--mode", mode]
    main(args)
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(raw).hexdigest() and path.read_bytes() == raw
    assert export_sarif(output)["runs"][0]["results"]
    with pytest.raises(FileExistsError):
        main(args)
    capsys.readouterr()
    main(["mobile-review-catalog"])
    assert json.loads(capsys.readouterr().out)["skills"][0]["id"] == "offensive-mobile"
    path.write_bytes(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode=mode)


@pytest.mark.parametrize("mode,raw", MODE_INPUTS)
def test_outside_scope_and_symlinks_are_rejected(tmp_path, monkeypatch, mode, raw):
    root = tmp_path / "private"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError):
        review_file(outside, authorized=True, mode=mode)
    source = root / "input"
    source.write_bytes(raw)
    args = ["mobile-review" if mode == "normalized" else "mobile-config-review", "--input", str(source), "--out", str(tmp_path / "forbidden-output"), "--authorized"]
    if mode != "normalized":
        args += ["--mode", mode]
    with pytest.raises(ValueError):
        main(args)
    assert not (tmp_path / "forbidden-output").exists()
    link = root / "linked"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        review_file(link, authorized=True, mode=mode)


@pytest.mark.parametrize("raw", [b'{', b'{"secret":"PRIVATE","secret":"PRIVATE"}', b'{"number":NaN}', b'\xffPRIVATE'])
def test_malformed_json_withholds_values(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path, authorized=True)
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_published_template_remains_insufficient_for_both_platforms():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "templates" / "HunterQA-mobile-review-template.json"
    report = review_evidence(json.loads(path.read_text()))
    assert len(report["records"]) == 14 and not report["findings"]
    assert all(p["status"] == "insufficient-evidence" for p in report["platforms"].values())


def test_native_receipts_distinguish_sarif_cases_without_exporting_identifiers(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    cases = []
    for label in ("PRIVATE-ONE", "PRIVATE-TWO"):
        _, report = native(tmp_path, monkeypatch, "ios-info", plistlib.dumps({"CFBundleIdentifier": label, "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}))
        serialized = json.dumps(report)
        assert label not in serialized
        output = tmp_path / (label + ".json")
        output.write_text(serialized)
        cases.append(export_sarif(output)["runs"][0]["results"][0])
    assert cases[0]["properties"]["assessmentCase"] != cases[1]["properties"]["assessmentCase"]
    assert cases[0]["partialFingerprints"] != cases[1]["partialFingerprints"]


@pytest.mark.parametrize("mode,raw", [
    ("android-manifest", manifest(children='<activity/>' * 201)),
    ("android-manifest", manifest(permissions='<permission/>' * 101)),
    ("android-network-security", '<network-security-config>' + '<base-config/>' * 101 + '</network-security-config>'),
    ("ios-info", plistlib.dumps({"NSAppTransportSecurity": {"NSExceptionDomains": {"private-" + str(i): {} for i in range(101)}}})),
    ("ios-info", plistlib.dumps({"CFBundleURLTypes": [{}] * 101})),
])
def test_native_selected_record_bounds(tmp_path, monkeypatch, mode, raw):
    path = tmp_path / "bounded.xml"
    path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError):
        review_file(path, authorized=True, mode=mode)


def test_utf16_entity_declarations_cannot_bypass_xml_guards(tmp_path, monkeypatch):
    raw = '<!DOCTYPE manifest [<!ENTITY xxe SYSTEM "file:///PRIVATE-NEVER-OPEN">]><manifest><application>&xxe;</application></manifest>'.encode("utf-16")
    path = tmp_path / "bad.xml"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_file(path, authorized=True, mode="android-manifest")
    assert "PRIVATE" not in "".join(traceback.format_exception(exc.value))


def test_unknown_mode_never_reads_an_input(tmp_path):
    with pytest.raises(ValueError):
        review_file(tmp_path / "does-not-exist", authorized=True, mode="adb-execute")
