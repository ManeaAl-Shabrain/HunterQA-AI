"""Offline Android/iOS declaration and bounded decoded-XML configuration review."""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date, datetime, timezone

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from .bounty import _approved_file
from .source_files import read_bounded

MAX_BYTES = 1_048_576
MAX_FINDINGS = 500
MAX_XML_NODES = 5000
MAX_XML_DEPTH = 32
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
ANDROID = "{http://schemas.android.com/apk/res/android}"
AREAS = {
    "storage": ("sensitive_data_protected", "secrets_in_logs", "backup_policy_reviewed"),
    "transport": ("tls_validation_enforced", "cleartext_permitted", "pinning_policy_reviewed"),
    "webview": ("untrusted_content_allowed", "native_bridge_restricted", "file_access_restricted"),
    "authentication": ("biometric_authentication_used", "biometric_crypto_binding", "session_revocation_reviewed", "local_authorization_reviewed"),
    "links": ("input_validation_reviewed", "ownership_association_verified", "sensitive_action_requires_auth"),
    "ipc": ("exported_surface_reviewed", "sender_authentication_reviewed", "least_privilege_reviewed"),
    "build": ("production_debug_disabled", "release_signing_verified", "dependency_patch_reviewed"),
}
MODES = ("normalized", "android-manifest", "android-network-security", "ios-info", "ios-entitlements")
RULES = {
    "storage": (("sensitive_data_protected", False, "Sensitive storage lacks declared protection", "Review actual storage classes, key protection and access controls.", "WARNING"),
        ("secrets_in_logs", True, "Sensitive logging is declared present", "Review redaction, log access and production logging policy without exporting secret values.", "WARNING"),
        ("backup_policy_reviewed", False, "Application backup policy has not been declared reviewed", "Review sensitive-data exclusions and platform-specific backup behavior.", "INFO")),
    "transport": (("tls_validation_enforced", False, "TLS server validation is declared absent", "Review actual certificate and hostname verification in the networking stack.", "WARNING"),
        ("cleartext_permitted", True, "Application policy declares cleartext transport permitted", "Review intended exceptions and actual network-stack enforcement.", "WARNING"),
        ("pinning_policy_reviewed", False, "Certificate-pinning policy has not been declared reviewed", "Determine whether pinning is appropriate for this threat model; absence is not automatically a vulnerability.", "INFO")),
    "webview": (("untrusted_content_allowed", True, "WebView declares untrusted content support", "Review navigation, origin separation and native bridge boundaries.", "INFO"),
        ("file_access_restricted", False, "WebView file access is not declared restricted", "Review actual file/content access and the application's intended document handling.", "INFO")),
    "authentication": (("session_revocation_reviewed", False, "Session revocation has not been declared reviewed", "Independently validate the application's session lifecycle and server-side invalidation.", "INFO"),
        ("local_authorization_reviewed", False, "Local authorization boundaries have not been declared reviewed", "Review protection of sensitive actions and the limits of local-only trust.", "INFO")),
    "links": (("input_validation_reviewed", False, "Link-handler input validation has not been declared reviewed", "Review accepted actions, origins and input validation independently.", "INFO"),
        ("ownership_association_verified", False, "Link ownership association has not been declared verified", "Review actual App Links/Universal Links association and fallback behavior.", "INFO"),
        ("sensitive_action_requires_auth", False, "Sensitive link actions lack declared authentication", "Review authentication and authorization at the actual action boundary.", "WARNING")),
    "ipc": tuple((f, False, title, "Review platform-specific sender identity, permissions and actual IPC authorization.", "INFO") for f, title in (
        ("exported_surface_reviewed", "Exported IPC surface has not been declared reviewed"), ("sender_authentication_reviewed", "IPC sender authentication has not been declared reviewed"), ("least_privilege_reviewed", "IPC privilege scope has not been declared reviewed"))),
    "build": (("production_debug_disabled", False, "Production debug controls are not declared disabled", "Review the intended build type and actual release configuration.", "WARNING"),
        ("release_signing_verified", False, "Release signing has not been declared independently verified", "Verify the actual signed artifact and release provenance with approved tooling.", "INFO"),
        ("dependency_patch_reviewed", False, "Mobile dependency/update policy has not been declared reviewed", "Review exact component versions and independently applicable advisories.", "INFO")),
}
REFERENCES = ["https://github.com/SnailSploit/Claude-Red/tree/main/Skills/mobile",
    "https://developer.android.com/guide/topics/manifest/application-element",
    "https://developer.android.com/privacy-and-security/security-config",
    "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity",
    "https://developer.apple.com/library/archive/technotes/tn2415/_index.html"]


def catalog():
    return [{"id": "offensive-mobile", "implementation": "offline-selected-android-ios-review",
        "native_input_modes": list(MODES[1:]), "device_execution_available": False,
        "active_exploitation_available": False, "fields": {a: list(fields) for a, fields in AREAS.items()},
        "required_evidence": "Private owner-normalized boolean observations or decoded Android XML / XML iOS property lists; signed artifacts, device behavior and effective enforcement remain unverified"}]


def _failure():
    raise ValueError("Unsupported mobile evidence shape, type or bounds; contents withheld") from None


def _decode(raw):
    def pairs(entries):
        result = {}
        for k, v in entries:
            if k in result:
                _failure()
            result[k] = v
        return result

    def constant(_):
        _failure()

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid mobile evidence JSON; contents withheld") from None


def validate_evidence(data):
    if not isinstance(data, dict) or set(data) != {"schema_version", "records"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _failure()
    if not isinstance(data["records"], list) or not 1 <= len(data["records"]) <= 140:
        _failure()
    ids, counts = set(), {}
    for r in data["records"]:
        if not isinstance(r, dict) or set(r) != {"id", "platform", "area", "observations"}:
            _failure()
        if not isinstance(r["id"], str) or not ID.fullmatch(r["id"]) or r["id"] in ids:
            _failure()
        ids.add(r["id"])
        if r["platform"] not in ("android", "ios") or not isinstance(r["area"], str) or r["area"] not in AREAS:
            _failure()
        pair = r["platform"], r["area"]
        counts[pair] = counts.get(pair, 0) + 1
        obs = r["observations"]
        if counts[pair] > 10 or not isinstance(obs, dict) or set(obs) != set(AREAS[r["area"]]) or not all(v is None or type(v) is bool for v in obs.values()):
            _failure()
    return data


def _report():
    return {"engine": "mobile-evidence-review", "schema_version": 1, "category": "Mobile", "skill": "offensive-mobile",
        "reviewed_at": datetime.now(timezone.utc).isoformat(), "findings": [], "records": [],
        "network_requests": 0, "device_actions_executed": 0, "external_tools_executed": 0,
        "referenced_files_opened": 0, "runtime_enforcement_verified": False, "signature_verified": False,
        "truncated": False, "candidates_not_retained": 0, "all_skills_automated": False,
        "real_world_effectiveness": "unverified", "references": REFERENCES,
        "limitations": ["Selected local declarations or configuration syntax only; no device/emulator interaction or app execution",
            "No APK/IPA/binary-XML/binary-plist decoding, decompilation, instrumentation, root/jailbreak or pinning bypass",
            "Manifest merging, resource references, API/OS defaults, inheritance, effective permissions, signed entitlements and runtime behavior are not resolved",
            "No app identifiers, component/permission names, URL schemes, domains, credentials, pin values or raw source values are exported; use neutral IDs",
            "Missing/unknown evidence is unassessed; exported components, links, sharing and exceptions may be intentional",
            "No network requests, association-domain retrieval, keychain/storage extraction, biometric bypass or signing verification; no complete standards coverage"]}


def _add(report, case, platform, key, title, fix, severity="WARNING"):
    if len(report["findings"]) >= MAX_FINDINGS:
        report["truncated"] = True
        report["candidates_not_retained"] += 1
        return
    report["findings"].append({"rule_id": "mobile-review." + platform + "." + key.replace("_", "-"),
        "skill": "offensive-mobile", "test_case": case, "platform": platform, "title": title,
        "severity": severity, "cwe": "CWE-693", "message": title + ". " + fix, "remediation": fix,
        "code": "", "file_path": "external-evidence", "line_start": 1, "line_end": 1,
        "engine": "mobile-evidence-review", "verification_status": "unverified"})


def _summarize(report):
    report["platforms"] = {}
    for p in ("android", "ios"):
        rows = [r for r in report["records"] if r["platform"] == p]
        report["platforms"][p] = {"records_reviewed": len(rows), "status": "not-assessed" if not rows else (
            "insufficient-evidence" if all(r["status"] == "insufficient-evidence" for r in rows) else "partial-offline-review")}
    return report


def review_evidence(data):
    validate_evidence(data)
    report = _report()
    for r in data["records"]:
        obs, area = r["observations"], r["area"]

        def cue(key, title, fix, severity="WARNING"):
            _add(report, r["id"], r["platform"], area + "." + key, title, fix, severity)

        for f, bad, title, fix, severity in RULES[area]:
            if obs[f] is not None and obs[f] == bad:
                cue(f, title, fix, severity)
        if area == "webview" and obs["untrusted_content_allowed"] is True and obs["native_bridge_restricted"] is False:
            cue("native_bridge_restricted", "WebView declares untrusted content with an unrestricted native bridge", "Review actual origin restrictions and native bridge authorization independently.")
        if area == "authentication" and obs["biometric_authentication_used"] is True and obs["biometric_crypto_binding"] is False:
            cue("biometric_crypto_binding", "Biometric authentication lacks declared cryptographic binding", "Review the actual protected operation, server authorization and platform key-access policy; this is not a demonstrated bypass.", "INFO")
        unknown = [f for f in obs if obs[f] is None]
        report["records"].append({"case": r["id"], "platform": r["platform"], "area": area, "unknown_fields": unknown,
            "status": "insufficient-evidence" if len(unknown) == len(obs) else "partial-declared-evidence"})
    return _summarize(report)


def _xml(raw, *, plist=False):
    try:
        root = ElementTree.fromstring(raw, forbid_dtd=not plist, forbid_entities=True, forbid_external=True)
    except (ElementTree.ParseError, DefusedXmlException, ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid or unsupported decoded XML; contents withheld") from None
    stack, count = [(root, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_XML_NODES or depth > MAX_XML_DEPTH or node.tag.startswith("{http://www.w3.org/2001/XInclude}"):
            _failure()
        stack.extend((c, depth + 1) for c in node)
    return root


def _abool(value):
    if value is None or value.startswith(("@", "${")):
        return None
    if value not in ("true", "false"):
        _failure()
    return value == "true"


def _native_case(report, platform, receipt, context, index=0, unknown=()):
    case = platform + "-" + receipt[:12] + "-" + context + "-" + str(index)
    report["records"].append({"case": case, "platform": platform, "context": context,
        "unknown_fields": list(unknown), "status": "selected-native-syntax-only"})
    return case


def _manifest(root, report, receipt):
    if root.tag != "manifest" or len(root.findall("application")) != 1:
        _failure()
    app = root.find("application")
    attributes = ("debuggable", "allowBackup", "usesCleartextTraffic", "testOnly", "requestLegacyExternalStorage")
    flags = {k: _abool(app.get(ANDROID + k)) for k in attributes}
    case = _native_case(report, "android", receipt, "app", unknown=[k for k, v in flags.items() if v is None])
    if all(v is None for v in flags.values()):
        report["records"][-1]["status"] = "insufficient-evidence"
    for key, title, fix, severity in (
        ("debuggable", "Manifest explicitly declares a debuggable application", "Review the intended build and actual production artifact.", "WARNING"),
        ("allowBackup", "Manifest explicitly permits application backup", "Review sensitive-data exclusions, extraction rules and OS/device behavior; backup alone is not a vulnerability.", "INFO"),
        ("usesCleartextTraffic", "Manifest explicitly declares cleartext transport permitted", "Review Network Security Config and platform precedence; the manifest flag does not prove effective cleartext access.", "WARNING"),
        ("testOnly", "Manifest declares a test-only build", "Review whether this artifact is intended for release; installation/signing is not verified.", "INFO"),
        ("requestLegacyExternalStorage", "Manifest requests legacy external storage behavior", "Review target/API applicability and actual storage protections.", "INFO")):
        if flags[key] is True:
            _add(report, case, "android", "manifest." + key.lower(), title, fix, severity)
    report["source_review"] = {"network_config_reference_present": app.get(ANDROID + "networkSecurityConfig") is not None,
        "backup_resource_reference_present": any(app.get(ANDROID + k) is not None for k in ("fullBackupContent", "dataExtractionRules")),
        "defaults_and_resource_references_resolved": False}
    components = [n for n in app if n.tag in ("activity", "activity-alias", "service", "receiver", "provider")]
    permissions = root.findall("permission")
    if len(components) > 200 or len(permissions) > 100:
        _failure()
    for i, node in enumerate(components, 1):
        exported = _abool(node.get(ANDROID + "exported"))
        c = _native_case(report, "android", receipt, "component", i, unknown=["exported"] if exported is None else [])
        if exported is True:
            _add(report, c, "android", "manifest.exported-component", "Component explicitly declares an exported entry point", "Review component/app permissions, caller identity and actual action authorization; exported does not mean vulnerable.", "INFO")
        elif exported is None and node.findall("intent-filter"):
            _add(report, c, "android", "manifest.unspecified-export", "Component with intent filters has no resolved explicit export contract", "Review target SDK, manifest merging and installation requirements; exposure is not inferred.", "INFO")
        for filt in node.findall("intent-filter"):
            browsable = any(n.get(ANDROID + "name") == "android.intent.category.BROWSABLE" for n in filt.findall("category"))
            view = any(n.get(ANDROID + "name") == "android.intent.action.VIEW" for n in filt.findall("action"))
            if browsable and view and filt.findall("data"):
                _add(report, c, "android", "manifest.link-handler", "Component declares a browsable link handler", "Independently review input validation, App Links association and sensitive-action authorization; no links are opened.", "INFO")
                break
    for i, node in enumerate(permissions, 1):
        if node.get(ANDROID + "protectionLevel") in ("normal", "dangerous"):
            p = _native_case(report, "android", receipt, "permission", i)
            _add(report, p, "android", "manifest.permission-level", "Custom permission declares a non-signature protection level", "Review the intended trust boundary; this permission class may be intentional.", "INFO")


def _network(root, report, receipt):
    if root.tag != "network-security-config":
        _failure()
    stack, contexts = [(root, False)], []
    while stack:
        node, debug = stack.pop()
        debug = debug or node.tag == "debug-overrides"
        if node.tag in ("base-config", "domain-config", "debug-overrides"):
            contexts.append((node, debug))
        stack.extend((c, debug) for c in reversed(list(node)))
    if not 1 <= len(contexts) <= 100:
        _failure()
    for i, (node, debug) in enumerate(contexts, 1):
        clear = _abool(node.get("cleartextTrafficPermitted")) if node.tag != "debug-overrides" else None
        c = _native_case(report, "android", receipt, "netconfig", i, unknown=["cleartextTrafficPermitted"] if clear is None else [])
        report["records"][-1]["debug_only_context"] = debug
        if clear is True:
            _add(report, c, "android", "network.cleartext", "Network Security Config explicitly permits cleartext in a selected scope", "Review domains, inheritance, manifest/platform precedence and actual networking behavior.")
        for cert in node.findall("trust-anchors/certificates"):
            if cert.get("src") == "user":
                _add(report, c, "android", "network.user-ca", "Selected scope declares trust in user-added certificate authorities", "Review intended trust and debug/release applicability; debug overrides require a debuggable app.", "INFO" if debug else "WARNING")
            if _abool(cert.get("overridePins")) is True:
                _add(report, c, "android", "network.pin-override", "Selected trust entry explicitly declares pin overriding", "Review intended trust-source and debug/release scope; no TLS or pinning bypass is performed.", "INFO")
        pins = node.findall("pin-set")
        if len(pins) > 1:
            _failure()
        if pins and pins[0].get("expiration") is not None:
            try:
                expired = date.fromisoformat(pins[0].get("expiration")) < datetime.now(timezone.utc).date()
            except ValueError:
                _failure()
            if expired:
                _add(report, c, "android", "network.expired-pin-set", "Selected pin-set declares a past expiration date", "Review pin maintenance and platform semantics; expired pinning does not mean ordinary TLS trust is disabled.", "INFO")


def _plist_value(node):
    if node.tag == "dict":
        children, out = list(node), {}
        if len(children) % 2:
            _failure()
        for k, v in zip(children[::2], children[1::2]):
            if k.tag != "key" or len(k) or (k.text or "") in out:
                _failure()
            out[k.text or ""] = _plist_value(v)
        return out
    if node.tag == "array":
        return [_plist_value(c) for c in node]
    if len(node):
        _failure()
    if node.tag in ("true", "false"):
        return node.tag == "true"
    if node.tag == "string":
        return node.text or ""
    if node.tag == "integer":
        try:
            if len(node.text or "") > 64:
                _failure()
            return int(node.text or "")
        except ValueError:
            _failure()
    if node.tag == "real":
        try:
            value = float(node.text or "")
            if not math.isfinite(value):
                _failure()
            return value
        except ValueError:
            _failure()
    if node.tag in ("data", "date"):
        return object()  # Unselected opaque values are not decoded or exported.
    _failure()


def _pbool(data, key):
    value = data.get(key)
    if key in data and type(value) is not bool:
        _failure()
    return value


def _array(data, key):
    if key not in data:
        return []
    value = data[key]
    if not isinstance(value, list) or len(value) > 100:
        _failure()
    return value


def _ios_info(data, report, receipt):
    ats = data.get("NSAppTransportSecurity", {})
    if not isinstance(ats, dict):
        _failure()
    ats_keys = ("NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking")
    sharing_keys = ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace")
    unknown = [k for k in ats_keys if k not in ats] + [k for k in sharing_keys if k not in data]
    c = _native_case(report, "ios", receipt, "info", unknown=unknown)
    if len(unknown) == len(ats_keys) + len(sharing_keys):
        report["records"][-1]["status"] = "insufficient-evidence"
    for key in ("NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"):
        if _pbool(ats, key) is True:
            _add(report, c, "ios", "ats." + key.lower(), "Info.plist declares a selected ATS exception", "Review exact scope and OS/key precedence; a global flag may be overridden by more specific keys, and effective transport is not verified.", "WARNING" if key == "NSAllowsArbitraryLoads" else "INFO")
    for key in ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"):
        if _pbool(data, key) is True:
            _add(report, c, "ios", "info." + key.lower(), "Info.plist declares document sharing/open-in-place behavior", "Review intended document access and actual sensitive data placement; sharing alone is not a vulnerability.", "INFO")
    domains = ats.get("NSExceptionDomains", {})
    if not isinstance(domains, dict) or len(domains) > 100:
        _failure()
    for i, policy in enumerate(domains.values(), 1):
        if not isinstance(policy, dict):
            _failure()
        domain_keys = ("NSExceptionAllowsInsecureHTTPLoads", "NSExceptionRequiresForwardSecrecy", "NSExceptionMinimumTLSVersion")
        d = _native_case(report, "ios", receipt, "ats-domain", i, unknown=[k for k in domain_keys if k not in policy])
        if not any(k in policy for k in domain_keys):
            report["records"][-1]["status"] = "insufficient-evidence"
        for key, bad in (("NSExceptionAllowsInsecureHTTPLoads", True), ("NSExceptionRequiresForwardSecrecy", False)):
            if _pbool(policy, key) is bad:
                _add(report, d, "ios", "ats." + key.lower(), "Selected ATS domain declares a transport-policy relaxation", "Review the intended server exception and actual OS/network-stack behavior.", "WARNING" if bad else "INFO")
        version = policy.get("NSExceptionMinimumTLSVersion")
        if version is not None and not isinstance(version, str):
            _failure()
        if version in ("TLSv1.0", "TLSv1.1"):
            _add(report, d, "ios", "ats.legacy-tls", "Selected ATS domain declares a legacy minimum TLS version", "Review server capabilities and platform enforcement; no connection or protocol negotiation is attempted.")
    for i, entry in enumerate(_array(data, "CFBundleURLTypes"), 1):
        if not isinstance(entry, dict):
            _failure()
        schemes = _array(entry, "CFBundleURLSchemes")
        if not all(isinstance(s, str) for s in schemes):
            _failure()
        if schemes:
            u = _native_case(report, "ios", receipt, "url-type", i)
            _add(report, u, "ios", "info.url-schemes", "Info.plist declares custom URL-scheme handlers", "Independently review handler input, ownership/collision behavior and action authorization; no schemes are opened.", "INFO")


def _entitlements(data, report, receipt):
    c = _native_case(report, "ios", receipt, "entitlements")
    if not any(k in data for k in ("get-task-allow", "keychain-access-groups", "com.apple.security.application-groups", "com.apple.developer.associated-domains")) and not any(k.startswith("com.apple.private.") for k in data):
        report["records"][-1]["status"] = "insufficient-evidence"
    if _pbool(data, "get-task-allow") is True:
        _add(report, c, "ios", "entitlements.debug", "Entitlements declare debugger task access", "Review intended build, actual code signature and provisioning profile; source entitlements do not prove effective permission.")
    for key in ("keychain-access-groups", "com.apple.security.application-groups", "com.apple.developer.associated-domains"):
        values = _array(data, key)
        if not all(isinstance(v, str) for v in values):
            _failure()
        if values and (key != "keychain-access-groups" or len(values) > 1):
            _add(report, c, "ios", "entitlements." + key.replace(".", "-"), "Entitlements declare selected sharing or association capabilities", "Review actual signed scope, app trust and domain association; no shared storage or network service is accessed.", "INFO")
    for i, (key, value) in enumerate(data.items(), 1):
        if key.startswith("com.apple.private.") and value:
            p = _native_case(report, "ios", receipt, "private-ent", i)
            _add(report, p, "ios", "entitlements.private", "Source declares a private entitlement requiring platform review", "Verify actual signing eligibility and provisioning; declaration is not proof of granted privilege.", "INFO")


def review_file(path, *, authorized=False, mode="normalized"):
    if not authorized:
        raise PermissionError("Mobile evidence review requires explicit authorization")
    if mode not in MODES:
        _failure()
    raw = read_bounded(_approved_file(path), MAX_BYTES)
    receipt = hashlib.sha256(raw).hexdigest()
    if mode == "normalized":
        report = review_evidence(_decode(raw))
    else:
        report = _report()
        root = _xml(raw, plist=mode.startswith("ios-"))
        if mode == "android-manifest":
            _manifest(root, report, receipt)
        elif mode == "android-network-security":
            _network(root, report, receipt)
        else:
            if root.tag != "plist" or root.get("version") != "1.0" or len(root) != 1 or root[0].tag != "dict":
                _failure()
            data = _plist_value(root[0])
            (_ios_info if mode == "ios-info" else _entitlements)(data, report, receipt)
        _summarize(report)
        report["limitations"].append("Decoded XML only; native case IDs derive from input receipts and record order, not app identities; no complete platform schema/validity check or source line location is claimed")
    report.update(input_sha256=receipt, input_mode=mode)
    return report
