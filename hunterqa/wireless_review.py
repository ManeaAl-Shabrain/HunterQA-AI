"""Offline wireless policy evidence and a narrow non-executing hostapd reader."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 524288
MAX_RECORDS_PER_SKILL = 10
MAX_FINDINGS = 500
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PATCH = ("applied", "missing", "not-applicable", "unknown")
# All observations are nullable. These are review contracts, not radio attacks.
PROFILES = {
    "wifi": {"modern_wpa_enabled": "bool", "legacy_security_enabled": "bool", "client_isolation": "bool", "management_plane_isolated": "bool"},
    "wifi-recon": {"inventory_reviewed": "bool", "ownership_mapped": "bool", "band_coverage_reviewed": "bool"},
    "wpa2-psk": {"legacy_wpa_enabled": "bool", "tkip_pairwise_enabled": "bool", "passphrase_policy_verified": "bool"},
    "wpa3-sae": {"transition_mode": "bool", "pmf_required": "bool", "sae_patch_status": PATCH},
    "wpa-enterprise": {"server_certificate_validation": "bool", "trusted_server_names_configured": "bool", "password_based_eap_allowed": "bool"},
    "wps": {"enabled": "bool", "pin_enrollment_enabled": "bool", "lockout_enforced": "bool"},
    "evil-twin": {"auto_join_untrusted_networks": "bool", "server_identity_validation": "bool", "rogue_ap_monitoring": "bool"},
    "krack-fragattacks": {"krack_patch_status": PATCH, "fragattacks_patch_status": PATCH},
    "deauth-disassoc": {"pmf_required": "bool", "legacy_clients_present": "bool", "legacy_exception_reviewed": "bool"},
    "bluetooth-ble": {"le_secure_connections": "bool", "authenticated_pairing": "bool", "sensitive_gatt_authorization": "bool"},
    "bluetooth-classic": {"secure_simple_pairing": "bool", "legacy_pairing_allowed": "bool", "minimum_key_policy_enforced": "bool"},
    "zigbee-thread-matter": {"technology": ("zigbee", "thread", "matter", "unknown"), "authenticated_commissioning": "bool", "default_shared_keys_in_use": "bool", "commissioning_window_limited": "bool"},
    "z-wave": {"security_mode": ("s2-authenticated", "s2-access-control", "s2-unauthenticated", "s0", "none", "unknown"), "inclusion_identity_verified": "bool"},
    "lorawan-sub-ghz": {"technology": ("lorawan", "proprietary", "unknown"), "activation_mode": ("otaa", "abp", "not-applicable", "unknown"), "frame_counter_validation": "bool", "unique_device_keys": "bool", "replay_protection": "bool"},
}

# field, observed value, title, remediation, triage label.
RULES = {
    "wifi": (
        ("modern_wpa_enabled", False, "Modern WPA/RSN protection is not declared enabled", "Review the selected network's protection and any intentional guest/alternative design.", "INFO"),
        ("legacy_security_enabled", True, "Legacy wireless protection is declared enabled", "Review migration from WEP/WPA1 and approved compatibility exceptions.", "WARNING"),
        ("client_isolation", False, "Client isolation is declared disabled", "Review intended peer connectivity and segmentation; isolation is not suitable for every network.", "INFO"),
        ("management_plane_isolated", False, "Wireless management-plane isolation is not declared", "Review administrative access boundaries and separate management access where appropriate.", "INFO")),
    "wifi-recon": tuple((f, False, title, "Review the privately mapped inventory and collection limitations; no airspace scan is performed.", "INFO") for f, title in (
        ("inventory_reviewed", "Wireless inventory has not been declared reviewed"), ("ownership_mapped", "Wireless inventory ownership has not been declared mapped"), ("band_coverage_reviewed", "Wireless inventory band coverage has not been declared reviewed"))),
    "wpa2-psk": (
        ("legacy_wpa_enabled", True, "Personal network permits declared legacy WPA", "Review disabling legacy WPA while preserving approved client compatibility.", "WARNING"),
        ("tkip_pairwise_enabled", True, "Personal network permits declared TKIP pairwise protection", "Review migration to supported modern pairwise ciphers.", "WARNING"),
        ("passphrase_policy_verified", False, "Personal-network passphrase policy has not been declared verified", "Have the owner independently review credential strength, uniqueness and rotation; do not submit keys to this tool.", "INFO")),
    "wpa3-sae": (
        ("transition_mode", True, "SAE deployment declares a transition mode", "Review downgrade exposure and compatibility needs; transition mode alone is not proof of vulnerability.", "INFO"),
        ("pmf_required", False, "Selected BSS does not declare PMF required for all stations", "Review SAE and legacy-client PMF behavior separately; this does not prove an SAE protection bypass.", "INFO"),
        ("sae_patch_status", "missing", "SAE security updates are declared missing", "Confirm vendor applicability and install approved updates; no Dragonblood exploitability is inferred.", "WARNING")),
    "wpa-enterprise": (
        ("server_certificate_validation", False, "Enterprise client server-certificate validation is declared disabled", "Validate the intended authentication server using approved trust configuration.", "WARNING"),
        ("trusted_server_names_configured", False, "Enterprise client has no declared trusted-server-name restriction", "Review exact expected server identity and certificate trust policy.", "WARNING"),
        ("password_based_eap_allowed", True, "Enterprise policy permits declared password-based EAP", "Review method selection, server validation and credential protections; this observation alone is not a credential compromise.", "INFO")),
    "wps": (("enabled", True, "WPS is declared enabled", "Review whether WPS is needed and restrict provisioning to an approved process.", "INFO"),),
    "evil-twin": (
        ("auto_join_untrusted_networks", True, "Client policy permits automatic joining of untrusted networks", "Restrict automatic association to approved network profiles.", "WARNING"),
        ("server_identity_validation", False, "Relevant client authentication lacks declared server identity validation", "Review the actual authentication method and its intended server binding.", "WARNING"),
        ("rogue_ap_monitoring", False, "Rogue access-point monitoring is declared unavailable", "Review detection coverage and incident handling; no rogue access point is created or discovered here.", "INFO")),
    "krack-fragattacks": tuple((f, "missing", title, "Verify device/vendor applicability and approved updates; no runtime vulnerability test is performed.", "WARNING") for f, title in (
        ("krack_patch_status", "KRACK-related updates are declared missing"), ("fragattacks_patch_status", "FragAttacks-related updates are declared missing"))),
    "deauth-disassoc": (("pmf_required", False, "Selected wireless policy does not require PMF", "Review management-frame protection and legacy exceptions; PMF does not prevent every radio denial of service.", "INFO"),),
    "bluetooth-ble": (
        ("le_secure_connections", False, "BLE Secure Connections is declared unavailable", "Review device capability and the approved pairing policy.", "INFO"),
        ("authenticated_pairing", False, "BLE pairing lacks declared peer authentication", "Review the pairing association method and application threat model.", "WARNING"),
        ("sensitive_gatt_authorization", False, "Sensitive GATT access lacks declared authorization", "Enforce application-appropriate authorization for sensitive attributes.", "WARNING")),
    "bluetooth-classic": (
        ("secure_simple_pairing", False, "Bluetooth Classic lacks declared Secure Simple Pairing", "Review supported pairing mechanisms and legacy compatibility.", "INFO"),
        ("legacy_pairing_allowed", True, "Bluetooth Classic permits declared legacy pairing", "Review removal of unnecessary legacy pairing exceptions.", "INFO"),
        ("minimum_key_policy_enforced", False, "Bluetooth encryption-key policy is not declared enforced", "Review negotiated key-size enforcement and vendor updates; this is not a KNOB/BlueBorne finding.", "WARNING")),
    "zigbee-thread-matter": (),
    "z-wave": (
        ("security_mode", "none", "Z-Wave protection is declared absent", "Review secure inclusion and device capability.", "WARNING"),
        ("security_mode", "s0", "Z-Wave deployment declares legacy S0 security", "Review S2 migration where supported and approved device exceptions.", "INFO"),
        ("security_mode", "s2-unauthenticated", "Z-Wave deployment declares unauthenticated S2 inclusion", "Review whether authenticated inclusion is appropriate for this device.", "INFO"),
        ("inclusion_identity_verified", False, "Z-Wave inclusion identity has not been declared verified", "Verify the intended device identity through the approved inclusion process.", "WARNING")),
    "lorawan-sub-ghz": (),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red#wireless", "https://w1.fi/hostapd/",
    "https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/main/hostapd/hostapd.conf",
    "https://doi.org/10.6028/NIST.SP.800-121r2-upd1", "https://lora-alliance.org/resource_hub/lorawan-security-faq/",
    "https://docs.silabs.com/zigbee/latest/using-installation-codes-with-zigbee-devices/",
    "https://www.silabs.com/whitepapers/z-wave-security"]


def catalog():
    return [{"id": "offensive-" + key, "implementation": "offline-selected-policy-review",
        "radio_execution_available": False, "active_exploitation_available": False,
        "fields": {f: "boolean-or-null" if kind == "bool" else [*kind, None] for f, kind in fields.items()},
        "required_evidence": "Owner-normalized applicable configuration and independent source verification; no radio behavior, credentials or exploitability is validated"}
        for key, fields in PROFILES.items()]


def _decode(raw):
    def pairs(entries):
        result = {}
        for k, v in entries:
            if k in result:
                raise ValueError("Duplicate key")
            result[k] = v
        return result

    def constant(_):
        raise ValueError("Non-finite JSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid wireless evidence JSON; contents withheld") from None


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Wireless evidence requires exact schema version 1 fields")
    records = data["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= len(PROFILES) * MAX_RECORDS_PER_SKILL:
        raise ValueError("Wireless record count exceeds supported bounds")
    ids, counts = set(), {}
    for row in records:
        if not isinstance(row, dict) or set(row) != {"id", "skill", "observations"}:
            raise ValueError("Wireless record has missing or unknown fields; contents withheld")
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]) or row["id"] in ids:
            raise ValueError("Wireless records require distinct neutral lowercase IDs")
        ids.add(row["id"])
        if not isinstance(row["skill"], str) or row["skill"] not in {"offensive-" + k for k in PROFILES}:
            raise ValueError("Unsupported wireless skill")
        counts[row["skill"]] = counts.get(row["skill"], 0) + 1
        if counts[row["skill"]] > MAX_RECORDS_PER_SKILL:
            raise ValueError("At most ten records per wireless skill")
        fields = PROFILES[row["skill"].removeprefix("offensive-")]
        obs = row["observations"]
        if not isinstance(obs, dict) or set(obs) != set(fields):
            raise ValueError("Wireless observations require exact profile fields; contents withheld")
        for name, kind in fields.items():
            value = obs[name]
            if value is None:
                continue
            valid = type(value) is bool if kind == "bool" else isinstance(value, str) and value in kind
            if not valid:
                raise ValueError("Unsupported typed wireless observation; contents withheld")
    return data


def _extra(key, o, cue):
    if key == "wps" and o["enabled"] is True:
        if o["pin_enrollment_enabled"] is True:
            cue("pin_enrollment_enabled", "WPS PIN enrollment is declared enabled", "Review disabling unnecessary PIN enrollment and verify approved provisioning.")
            if o["lockout_enforced"] is False:
                cue("lockout_enforced", "Declared WPS PIN enrollment lacks lockout enforcement", "Review rate/lockout policy without attempting PIN guesses.")
    elif key == "deauth-disassoc" and o["legacy_clients_present"] is True and o["legacy_exception_reviewed"] is False:
        cue("legacy_exception_reviewed", "Legacy-client PMF exception has not been declared reviewed", "Review actual compatibility needs and the exposure of legacy stations.", "INFO")
    elif key == "zigbee-thread-matter" and o["technology"] in ("zigbee", "thread", "matter"):
        for field, bad, title in (("authenticated_commissioning", False, "Mesh/commissioning policy lacks declared peer authentication"),
                ("default_shared_keys_in_use", True, "Selected technology declares default/shared commissioning keys"),
                ("commissioning_window_limited", False, "Selected technology declares an unrestricted commissioning window")):
            if o[field] is bad:
                cue(field, title, "Review the selected technology/version and its approved commissioning and key-management policy; no protocol attack is executed.")
    elif key == "lorawan-sub-ghz":
        if o["technology"] == "lorawan":
            if o["activation_mode"] == "abp":
                cue("activation_mode", "LoRaWAN deployment declares ABP activation", "Review session lifecycle and counter persistence; ABP alone is not a vulnerability.", "INFO")
            if o["frame_counter_validation"] is False:
                cue("frame_counter_validation", "LoRaWAN frame-counter validation is declared disabled", "Review device/network-server replay and counter policy.")
        if o["technology"] in ("lorawan", "proprietary"):
            if o["unique_device_keys"] is False:
                cue("unique_device_keys", "Selected radio technology declares reused device keys", "Review device-specific credentials and key lifecycle; no key values are requested.")
            if o["replay_protection"] is False:
                cue("replay_protection", "Selected radio technology lacks declared replay protection", "Review applicable freshness and replay defenses; no replay frames are transmitted.")


def review_evidence(data):
    validate_evidence(data)
    findings, records = [], []
    dropped = 0
    for row in data["records"]:
        key = row["skill"].removeprefix("offensive-")
        obs = row["observations"]

        def cue(field, title, fix, severity="WARNING"):
            nonlocal dropped
            if len(findings) >= MAX_FINDINGS:
                dropped += 1
                return
            findings.append({"rule_id": "wireless." + key + "." + field.replace("_", "-"),
                "skill": row["skill"], "test_case": row["id"], "title": title, "severity": severity,
                "cwe": "CWE-693", "message": title + ". " + fix, "remediation": fix,
                "file_path": "external-evidence", "line_start": 1, "line_end": 1, "code": "",
                "engine": "wireless-evidence-review", "verification_status": "unverified"})

        for field, bad, title, fix, severity in RULES[key]:
            if obs[field] is not None and obs[field] == bad:
                cue(field, title, fix, severity)
        _extra(key, obs, cue)
        unknown = [f for f in obs if obs[f] is None or obs[f] == "unknown"]
        records.append({"case": row["id"], "skill": row["skill"], "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    skills = []
    for spec in catalog():
        selected = [r for r in records if r["skill"] == spec["id"]]
        skills.append({**spec, "records_reviewed": len(selected), "status": "not-assessed" if not selected else (
            "insufficient-evidence" if all(r["status"] == "insufficient-evidence" for r in selected) else "partial-offline-review")})
    return {"engine": "wireless-evidence-review", "schema_version": 1, "category": "Wireless",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "skills": skills, "records": records,
        "findings": findings, "truncated": bool(dropped), "candidates_not_retained": dropped,
        "network_requests": 0, "radio_actions_executed": 0, "external_tools_executed": 0,
        "all_skills_automated": False, "real_world_effectiveness": "unverified", "references": REFERENCES,
        "limitations": ["Selected local declarations only; no radio inventory, packet/handshake parsing or RF coverage measurement",
            "No monitor mode, scanning, transmission, deauthentication, rogue AP, credential capture, cracking, replay or exploitation",
            "Missing records, null and unknown fields remain unassessed; declarations and patch applicability require independent verification",
            "No SSID, BSSID, MAC, location, identity, credential, key, raw configuration or packet values are exported; use neutral IDs",
            "PMF does not address every denial of service; compatibility and technology-specific applicability require owner review",
            "No confirmed KRACK, FragAttacks, Dragonblood, KNOB, BlueBorne or protocol-level vulnerability classification; no standards certification"]}


def review_file(path, *, authorized=False):
    if not authorized:
        raise PermissionError("Wireless evidence review requires explicit authorization")
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    report = review_evidence(_decode(raw))
    report["input_sha256"] = hashlib.sha256(raw).hexdigest()
    report["input_mode"] = "owner-normalized-json"
    return report


def review_hostapd(path, *, authorized=False):
    """Read a selected single-BSS config; never open referenced paths or execute it."""
    if not authorized:
        raise PermissionError("hostapd source review requires explicit authorization")
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("Unsupported hostapd encoding; contents withheld") from None
    integer = {"wpa": range(4), "ieee80211w": range(3), "wps_state": range(3), "ap_isolate": range(2)}
    sets = {"wpa_key_mgmt": {"WPA-PSK", "WPA-PSK-SHA256", "FT-PSK", "SAE", "FT-SAE", "WPA-EAP", "FT-EAP", "WPA-EAP-SHA256", "WPA-EAP-SUITE-B", "WPA-EAP-SUITE-B-192", "OWE"},
        "rsn_pairwise": {"TKIP", "CCMP", "GCMP", "CCMP-256", "GCMP-256"},
        "wpa_pairwise": {"TKIP", "CCMP", "GCMP", "CCMP-256", "GCMP-256"}}
    values, locations, ignored = {}, {}, 0
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line or "\x00" in line:
            raise ValueError("Unsupported hostapd syntax; contents withheld")
        key, value = (s.strip() for s in line.split("=", 1))
        if key in {"bss", "include"} or key.startswith("rsn_override"):
            raise ValueError("Multiple BSS, includes and RSN overrides are outside this parser's scope")
        if key not in integer and key not in sets:
            ignored += 1
            continue
        if key in values:
            raise ValueError("Duplicate selected hostapd directive; contents withheld")
        if key in integer:
            if not value.isascii() or not value.isdigit() or len(value) > 1 or int(value) not in integer[key]:
                raise ValueError("Unsupported selected hostapd value; contents withheld")
            parsed = int(value)
        else:
            parts = value.split()
            if not parts or not set(parts) <= sets[key] or len(set(parts)) != len(parts):
                raise ValueError("Unsupported selected hostapd option; contents withheld")
            parsed = set(parts)
        values[key], locations[key] = parsed, number
    if not values:
        raise ValueError("No supported explicit hostapd security settings found")
    rows = []
    receipt = hashlib.sha256(raw).hexdigest()

    def record(skill, **updates):
        rows.append({"id": "hostapd-" + receipt[:12] + "-" + skill, "skill": "offensive-" + skill,
            "observations": {f: updates.get(f) for f in PROFILES[skill]}})

    wpa, pmf, km = values.get("wpa"), values.get("ieee80211w"), values.get("wpa_key_mgmt", set())
    record("wifi", modern_wpa_enabled=bool(wpa & 2) if wpa is not None else None,
        legacy_security_enabled=bool(wpa & 1) if wpa is not None else None,
        client_isolation=bool(values["ap_isolate"]) if "ap_isolate" in values else None)
    if wpa != 0 and km & {"WPA-PSK", "WPA-PSK-SHA256", "FT-PSK"}:
        pairwise = [values.get(k) for bit, k in ((1, "wpa_pairwise"), (2, "rsn_pairwise")) if wpa is not None and wpa & bit]
        tkip = True if any(p and "TKIP" in p for p in pairwise) else False if pairwise and all(p is not None for p in pairwise) else None
        record("wpa2-psk", legacy_wpa_enabled=bool(wpa & 1) if wpa is not None else None, tkip_pairwise_enabled=tkip)
    if wpa != 0 and km & {"SAE", "FT-SAE"}:
        record("wpa3-sae", transition_mode=bool(km & {"WPA-PSK", "WPA-PSK-SHA256", "FT-PSK"}), pmf_required=pmf == 2 if pmf is not None else None)
    if "wps_state" in values:
        record("wps", enabled=values["wps_state"] != 0)
    if pmf is not None:
        record("deauth-disassoc", pmf_required=pmf == 2)
    report = review_evidence({"schema_version": 1, "records": rows})
    report.update(input_sha256=receipt, input_mode="selected-single-bss-hostapd",
        source_review={"selected_directive_lines": locations, "unreviewed_directive_count": ignored,
            "runtime_configuration_verified": False, "referenced_files_opened": 0})
    report["limitations"].extend(["hostapd review covers seven explicit directives only; absent defaults, external files, group ciphers, client EAP policy and runtime behavior are not inferred",
        "RSN cipher defaults are intentionally not inherited; credentials/identifiers and unknown directive values are ignored, not exported",
        "A hostapd file is not validated as runnable or complete; current driver/version behavior and override/configuration sources require independent review"])
    return report
