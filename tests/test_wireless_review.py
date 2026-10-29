"""Owned policy/configuration fixtures only; no wireless hardware or packets."""
import copy
import hashlib
import json

import pytest

from hunterqa.cli import main
from hunterqa.wireless_review import MAX_BYTES, PROFILES, catalog, review_evidence, review_file, review_hostapd

CASES = (
    ("wifi", {"modern_wpa_enabled": True, "legacy_security_enabled": False, "client_isolation": True, "management_plane_isolated": True}, {"legacy_security_enabled": True}, {"legacy-security-enabled"}),
    ("wifi-recon", {"inventory_reviewed": True, "ownership_mapped": True, "band_coverage_reviewed": True}, {"band_coverage_reviewed": False}, {"band-coverage-reviewed"}),
    ("wpa2-psk", {"legacy_wpa_enabled": False, "tkip_pairwise_enabled": False, "passphrase_policy_verified": True}, {"tkip_pairwise_enabled": True}, {"tkip-pairwise-enabled"}),
    ("wpa3-sae", {"transition_mode": False, "pmf_required": True, "sae_patch_status": "applied"}, {"sae_patch_status": "missing"}, {"sae-patch-status"}),
    ("wpa-enterprise", {"server_certificate_validation": True, "trusted_server_names_configured": True, "password_based_eap_allowed": False}, {"server_certificate_validation": False}, {"server-certificate-validation"}),
    ("wps", {"enabled": False, "pin_enrollment_enabled": False, "lockout_enforced": True}, {"enabled": True, "pin_enrollment_enabled": True, "lockout_enforced": False}, {"enabled", "pin-enrollment-enabled", "lockout-enforced"}),
    ("evil-twin", {"auto_join_untrusted_networks": False, "server_identity_validation": True, "rogue_ap_monitoring": True}, {"auto_join_untrusted_networks": True}, {"auto-join-untrusted-networks"}),
    ("krack-fragattacks", {"krack_patch_status": "applied", "fragattacks_patch_status": "applied"}, {"fragattacks_patch_status": "missing"}, {"fragattacks-patch-status"}),
    ("deauth-disassoc", {"pmf_required": True, "legacy_clients_present": False, "legacy_exception_reviewed": True}, {"pmf_required": False}, {"pmf-required"}),
    ("bluetooth-ble", {"le_secure_connections": True, "authenticated_pairing": True, "sensitive_gatt_authorization": True}, {"authenticated_pairing": False}, {"authenticated-pairing"}),
    ("bluetooth-classic", {"secure_simple_pairing": True, "legacy_pairing_allowed": False, "minimum_key_policy_enforced": True}, {"legacy_pairing_allowed": True}, {"legacy-pairing-allowed"}),
    ("zigbee-thread-matter", {"technology": "zigbee", "authenticated_commissioning": True, "default_shared_keys_in_use": False, "commissioning_window_limited": True}, {"default_shared_keys_in_use": True}, {"default-shared-keys-in-use"}),
    ("z-wave", {"security_mode": "s2-authenticated", "inclusion_identity_verified": True}, {"security_mode": "none"}, {"security-mode"}),
    ("lorawan-sub-ghz", {"technology": "lorawan", "activation_mode": "otaa", "frame_counter_validation": True, "unique_device_keys": True, "replay_protection": True}, {"frame_counter_validation": False}, {"frame-counter-validation"}),
)


def evidence(key="wifi", **updates):
    return {"schema_version": 1, "records": [{"id": "owned-one", "skill": "offensive-" + key,
        "observations": {f: updates.get(f) for f in PROFILES[key]}}]}


def rules(report):
    return {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("key,quiet,updates,expected", CASES)
def test_all_fourteen_profiles_have_positive_and_negative_controls(key, quiet, updates, expected):
    baseline = review_evidence(evidence(key, **quiet))
    assert not baseline["findings"]
    assert baseline["radio_actions_executed"] == baseline["network_requests"] == baseline["external_tools_executed"] == 0
    assert baseline["real_world_effectiveness"] == "unverified"
    assert not baseline["all_skills_automated"]
    assert [s["id"] for s in baseline["skills"] if s["status"] == "partial-offline-review"] == ["offensive-" + key]
    changed = {**quiet, **updates}
    report = review_evidence(evidence(key, **changed))
    assert rules(report) == {"wireless." + key + "." + name for name in expected}
    assert all(f["verification_status"] == "unverified" for f in report["findings"])


def test_catalog_and_unknown_values_do_not_claim_an_assessment_pass():
    assert len(catalog()) == 14
    data = {"schema_version": 1, "records": [{"id": key, "skill": "offensive-" + key,
        "observations": {f: None for f in fields}} for key, fields in PROFILES.items()]}
    report = review_evidence(data)
    assert not report["findings"]
    assert all(s["status"] == "insufficient-evidence" for s in report["skills"])
    assert all(r["unknown_fields"] for r in report["records"])


@pytest.mark.parametrize("key,updates,expected", [
    ("wps", {"enabled": False, "pin_enrollment_enabled": True, "lockout_enforced": False}, set()),
    ("wps", {"enabled": None, "pin_enrollment_enabled": True, "lockout_enforced": False}, set()),
    ("deauth-disassoc", {"legacy_clients_present": False, "legacy_exception_reviewed": False}, set()),
    ("deauth-disassoc", {"legacy_clients_present": True, "legacy_exception_reviewed": False}, {"legacy-exception-reviewed"}),
    ("zigbee-thread-matter", {"technology": "unknown", "default_shared_keys_in_use": True}, set()),
    ("zigbee-thread-matter", {"technology": "matter", "authenticated_commissioning": False}, {"authenticated-commissioning"}),
    ("lorawan-sub-ghz", {"technology": "proprietary", "activation_mode": "abp", "frame_counter_validation": False}, set()),
    ("lorawan-sub-ghz", {"technology": "lorawan", "activation_mode": "abp"}, {"activation-mode"}),
    ("lorawan-sub-ghz", {"technology": "unknown", "unique_device_keys": False}, set()),
    ("krack-fragattacks", {"krack_patch_status": "not-applicable", "fragattacks_patch_status": "unknown"}, set()),
    ("z-wave", {"security_mode": "s0"}, {"security-mode"}),
    ("z-wave", {"security_mode": "s2-unauthenticated"}, {"security-mode"}),
])
def test_technology_conditions_and_applicability(key, updates, expected):
    assert rules(review_evidence(evidence(key, **updates))) == {"wireless." + key + "." + name for name in expected}


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema_version=True),
    lambda d: d.update(ssid="PRIVATE-FIXTURE"),
    lambda d: d["records"][0].update(password="PRIVATE-FIXTURE"),
    lambda d: d["records"][0].update(skill="offensive-arbitrary-command"),
    lambda d: d["records"][0].update(id="00:11:22:33:44:55"),
    lambda d: d["records"][0]["observations"].update(modern_wpa_enabled=1),
    lambda d: d["records"][0]["observations"].update(modern_wpa_enabled="true"),
    lambda d: d["records"][0]["observations"].update(extra="PRIVATE-FIXTURE"),
    lambda d: d.update(records=[]),
    lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
])
def test_strict_schema_avoids_secrets_and_untyped_observations(mutate):
    data = evidence()
    mutate(data)
    with pytest.raises(ValueError) as exc:
        review_evidence(data)
    assert "PRIVATE-FIXTURE" not in str(exc.value)


def test_per_skill_record_limit_and_finding_caps(monkeypatch):
    import hunterqa.wireless_review as module
    row = evidence(legacy_security_enabled=True, client_isolation=False)["records"][0]
    data = {"schema_version": 1, "records": [{**copy.deepcopy(row), "id": "record-" + str(i)} for i in range(11)]}
    with pytest.raises(ValueError, match="ten records"):
        review_evidence(data)
    monkeypatch.setattr(module, "MAX_FINDINGS", 1)
    report = review_evidence({"schema_version": 1, "records": [row]})
    assert report["truncated"] and report["candidates_not_retained"] == 1
    assert len(report["findings"]) == 1


def hostapd(tmp_path, monkeypatch, text):
    path = tmp_path / "hostapd.conf"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    return path, review_hostapd(path, authorized=True)


def test_native_modern_personal_config_preserves_unknowns_and_redacts(tmp_path, monkeypatch):
    path, report = hostapd(tmp_path, monkeypatch,
        "interface=PRIVATE-INTERFACE\nssid=PRIVATE-SSID\nwpa_passphrase=PRIVATE-PASSPHRASE\n"
        "wpa_psk_file=/PRIVATE/PATH/never-open\nwpa=2\nwpa_key_mgmt=WPA-PSK\n"
        "rsn_pairwise=CCMP\nieee80211w=2\nwps_state=0\nap_isolate=1\n")
    assert not report["findings"]
    assert report["source_review"]["referenced_files_opened"] == 0
    assert report["source_review"]["unreviewed_directive_count"] == 4
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    serialized = json.dumps(report)
    for private in ("PRIVATE-INTERFACE", "PRIVATE-SSID", "PRIVATE-PASSPHRASE", "/PRIVATE/PATH"):
        assert private not in serialized
    psk = next(r for r in report["records"] if r["skill"] == "offensive-wpa2-psk")
    assert "passphrase_policy_verified" in psk["unknown_fields"]
    assert next(s for s in report["skills"] if s["id"] == "offensive-wpa-enterprise")["status"] == "not-assessed"


def test_native_legacy_security_cues_and_source_line_receipts(tmp_path, monkeypatch):
    _, report = hostapd(tmp_path, monkeypatch, "wpa=3\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nrsn_pairwise=TKIP\nieee80211w=0\nwps_state=2\nap_isolate=0\n")
    assert rules(report) == {"wireless.wifi.legacy-security-enabled", "wireless.wifi.client-isolation",
        "wireless.wpa2-psk.legacy-wpa-enabled", "wireless.wpa2-psk.tkip-pairwise-enabled",
        "wireless.wps.enabled", "wireless.deauth-disassoc.pmf-required"}
    assert report["source_review"]["selected_directive_lines"]["ieee80211w"] == 5


@pytest.mark.parametrize("config,expected", [
    ("wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\n", set()),
    ("wpa=2\nwpa_key_mgmt=SAE WPA-PSK\nrsn_pairwise=CCMP\nieee80211w=1\n", {"wireless.wpa3-sae.transition-mode", "wireless.wpa3-sae.pmf-required", "wireless.deauth-disassoc.pmf-required"}),
    ("wpa=2\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nrsn_pairwise=CCMP\n", set()),
    ("wpa=0\nwpa_key_mgmt=SAE\n", {"wireless.wifi.modern-wpa-enabled"}),
])
def test_native_sae_transition_and_inactive_legacy_directives(tmp_path, monkeypatch, config, expected):
    _, report = hostapd(tmp_path, monkeypatch, config)
    assert rules(report) == expected


def test_native_absent_rsn_defaults_remain_unknown(tmp_path, monkeypatch):
    _, report = hostapd(tmp_path, monkeypatch, "wpa=2\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\n")
    assert not report["findings"]
    psk = next(r for r in report["records"] if r["skill"] == "offensive-wpa2-psk")
    assert "tkip_pairwise_enabled" in psk["unknown_fields"]


@pytest.mark.parametrize("config", [
    "wpa=2\nwpa=1\n", "wpa=2\nbss=PRIVATE-BSS\n", "wpa=2\ninclude=/PRIVATE/PATH\n",
    "wpa=2\nrsn_override_mfp=0\n", "wpa=PRIVATE-FIXTURE\n", "ieee80211w=3\n",
    "wpa_key_mgmt=UNSUPPORTED-PRIVATE\n", "rsn_pairwise=CCMP CCMP\n",
    "wpa=2 # inline comments are outside the subset\n", "ssid=PRIVATE-FIXTURE\n",
    "not-an-assignment\n", "wpa=2\nvalue=\x00PRIVATE-FIXTURE\n",
])
def test_native_ambiguous_or_unsupported_scope_is_rejected_without_values(tmp_path, monkeypatch, config):
    path = tmp_path / "bad.conf"
    path.write_text(config)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError) as exc:
        review_hostapd(path, authorized=True)
    assert "PRIVATE" not in str(exc.value)


def test_no_dns_processes_or_radio_device_operations(tmp_path, monkeypatch):
    import socket
    import subprocess
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("No DNS"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("No external tools"))
    _, report = hostapd(tmp_path, monkeypatch, "ssid=$(DO-NOT-EXECUTE)\nwpa=2\nwpa_key_mgmt=SAE\nieee80211w=2\n")
    assert report["radio_actions_executed"] == report["network_requests"] == report["external_tools_executed"] == 0
    assert "DO-NOT-EXECUTE" not in json.dumps(report)


@pytest.mark.parametrize("reader,command,contents", [
    (review_file, "wireless-review", json.dumps(evidence(legacy_security_enabled=True))),
    (review_hostapd, "wireless-hostapd-review", "wpa=1\n"),
])
def test_cli_authorization_roots_private_create_only_and_sarif(tmp_path, monkeypatch, capsys, reader, command, contents):
    from hunterqa.sarif_export import export_sarif
    path, output = tmp_path / "input.txt", tmp_path / "report.json"
    path.write_text(contents)
    with pytest.raises(PermissionError):
        reader(path)
    monkeypatch.delenv("HUNTERQA_APPROVED_ROOTS", raising=False)
    with pytest.raises(ValueError):
        reader(path, authorized=True)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    args = [command, "--input", str(path), "--out", str(output), "--authorized"]
    main(args)
    report = json.loads(output.read_text())
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert export_sarif(output)["runs"][0]["results"]
    with pytest.raises(FileExistsError):
        main(args)
    capsys.readouterr()
    main(["wireless-review-catalog"])
    assert len(json.loads(capsys.readouterr().out)["skills"]) == 14
    path.write_bytes(b" " * (MAX_BYTES + 1))
    with pytest.raises(ValueError):
        reader(path, authorized=True)


@pytest.mark.parametrize("raw", [b'{', b'{"schema_version":1,"schema_version":2}', b'{"field":NaN}', b'\xff'])
def test_malformed_json_sanitizes_errors(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError, match="contents withheld"):
        review_file(path, authorized=True)


def test_published_template_remains_unknown_for_all_fourteen_contracts():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "templates" / "HunterQA-wireless-review-template.json"
    report = review_evidence(json.loads(path.read_text()))
    assert len(report["skills"]) == 14 and not report["findings"]
    assert all(s["status"] == "insufficient-evidence" for s in report["skills"])


@pytest.mark.parametrize("reader,contents,command", [
    (review_file, json.dumps(evidence()), "wireless-review"),
    (review_hostapd, "wpa=2\n", "wireless-hostapd-review"),
])
def test_outside_scope_and_symlinked_inputs_rejected(tmp_path, monkeypatch, reader, contents, command):
    root = tmp_path / "private"
    root.mkdir()
    outside = tmp_path / "outside-input"
    outside.write_text(contents)
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(root))
    with pytest.raises(ValueError):
        reader(outside, authorized=True)
    source = root / "input"
    source.write_text(contents)
    output = tmp_path / "outside-output"
    with pytest.raises(ValueError):
        main([command, "--input", str(source), "--out", str(output), "--authorized"])
    assert not output.exists()
    link = root / "symlink"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("OS does not allow creating symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        reader(link, authorized=True)


def test_native_receipts_distinguish_sarif_context_without_exposing_values(tmp_path, monkeypatch):
    from hunterqa.sarif_export import export_sarif
    cases = []
    for label in ("PRIVATE-ONE", "PRIVATE-TWO"):
        _, report = hostapd(tmp_path, monkeypatch, "ssid=" + label + "\nwpa=1\n")
        output = tmp_path / (label + ".json")
        output.write_text(json.dumps(report))
        assert label not in output.read_text()
        cases.append(export_sarif(output)["runs"][0]["results"][0])
    assert cases[0]["properties"]["assessmentCase"] != cases[1]["properties"]["assessmentCase"]
    assert cases[0]["partialFingerprints"] != cases[1]["partialFingerprints"]


def test_native_invalid_encoding_does_not_echo_input(tmp_path, monkeypatch):
    path = tmp_path / "bad.conf"
    path.write_bytes(b"\xffPRIVATE-FIXTURE")
    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(tmp_path))
    with pytest.raises(ValueError, match="contents withheld"):
        review_hostapd(path, authorized=True)
