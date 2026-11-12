"""Read-only pinned LDAPS collection and reusable selected AD attribute analysis."""
import hashlib
import hmac
import ipaddress
import math
import re
import ssl
import time

from . import ad_review, assessment_sessions, shared_quota
from .bounty import _approved_file, _decode_json
from .engagement import _expiry, digest, utcnow
from .scenario_assessment import runtime_identity
from .source_files import read_bounded
from .ssh_inspection import FIELDS as ENDPOINT_FIELDS, validate_contract as endpoint_contract

FIELDS = ENDPOINT_FIELDS - {"transport"} | {"mode", "tls_server_name", "base_dn", "ca_file", "max_pages", "page_size", "timeout_seconds", "minimum_password_length"}
ATTRIBUTES = ("objectClass", "userAccountControl", "adminCount", "memberOf", "member", "servicePrincipalName",
    "minPwdLength", "pwdProperties", "lockoutThreshold", "maxPwdAge", "trustType", "trustDirection", "trustAttributes", "flags")
NUMERIC = {name.lower() for name in ATTRIBUTES} - {"objectclass", "memberof", "member", "serviceprincipalname"}
FILTER = "(|(objectClass=domainDNS)(objectClass=user)(objectClass=group)(objectClass=trustedDomain)(objectClass=groupPolicyContainer))"


def contract(path, session_file, session_key):
    raw = read_bounded(_approved_file(path), 16384)
    data = _decode_json(raw)
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError("Invalid directory contract")
    endpoint_contract({key: data[key] for key in ENDPOINT_FIELDS - {"transport"}} | {"transport": "tcp-ssh-identification"})
    if (data["mode"] not in {"LAB", "LIVE"} or not isinstance(data["tls_server_name"], str)
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", data["tls_server_name"])
            or not isinstance(data["base_dn"], str) or not re.fullmatch(r"DC=[A-Za-z0-9-]{1,63}(?:,DC=[A-Za-z0-9-]{1,63}){1,8}", data["base_dn"], re.I)):
        raise ValueError("Explicit mode, TLS hostname and domain naming context required")
    if data["mode"] == "LAB" and ipaddress.ip_address(data["server_ip"]).is_global:
        raise ValueError("LAB directory must use an explicitly approved private endpoint")
    for key, low, high in (("max_pages", 1, 5), ("page_size", 1, 100), ("timeout_seconds", 1, 60), ("minimum_password_length", 8, 64)):
        if type(data[key]) is not int or not low <= data[key] <= high:
            raise ValueError("Directory limits exceed their bounds")
    ca_raw = None if data["ca_file"] is None else read_bounded(_approved_file(data["ca_file"]), 65536)
    try:
        context = ssl.create_default_context(cadata=ca_raw.decode("ascii") if ca_raw is not None else None)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ssl.SSLError, UnicodeError):
        raise ValueError("Invalid reviewed directory CA bundle") from None
    actors, binding = assessment_sessions.load(session_file, session_key)
    actor = actors.get("directory")
    if (set(actors) != {"directory"} or actor is None or actor["origin"] != f'https://{data["tls_server_name"]}:{data["server_port"]}'
            or set(actor["headers"]) != {"X-LDAP-Bind-DN", "Authorization"} or actor["cookies"] or actor["local_storage"]
            or not actor["headers"]["X-LDAP-Bind-DN"].casefold().endswith("," + data["base_dn"].casefold())):
        raise ValueError("A separate origin-bound directory reader credential is required")
    from importlib.metadata import PackageNotFoundError, version
    try:
        library_version = version("ldap3")
    except PackageNotFoundError:
        raise ValueError("Install the optional directory runtime: .[directory]") from None
    fingerprint = digest({"contract_sha256": hashlib.sha256(raw).hexdigest(), "session_binding": binding,
        "ca_sha256": hashlib.sha256(ca_raw).hexdigest() if ca_raw else None, "quota": shared_quota.configured_review(),
        "runtime": runtime_identity(), "ldap3": library_version})
    return data, actor["headers"], fingerprint, ca_raw


def preflight(path, session_file, session_key):
    data, _, fingerprint, _ = contract(path, session_file, session_key)
    return {"approval_sha256": fingerprint, "network_requests": 0, "maximum_operations": data["max_pages"] + 3,
        "read_only": True, "referrals": False, "automatic_range_queries": False, "credential_values_displayed": False}


def normalize(entries):
    if not isinstance(entries, list) or len(entries) > 500:
        raise ValueError("Directory entry bound exceeded")
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "searchResEntry":
            continue
        dn, attributes = entry.get("dn"), entry.get("raw_attributes")
        if not isinstance(dn, str) or not 1 <= len(dn) <= 2048 or not isinstance(attributes, dict):
            raise ValueError("Malformed directory entry")
        values = {}
        for key, raw_values in attributes.items():
            name = key.lower()
            if name not in {v.lower() for v in ATTRIBUTES}:
                continue  # Ranged memberships are not automatically expanded.
            if not isinstance(raw_values, list) or len(raw_values) > 100 or any(not isinstance(v, bytes) or len(v) > 2048 for v in raw_values):
                raise ValueError("Directory attribute bound exceeded")
            if name in NUMERIC:
                if raw_values:
                    if len(raw_values) != 1 or not re.fullmatch(rb"-?[0-9]{1,20}", raw_values[0]):
                        raise ValueError("Invalid directory integer")
                    value = int(raw_values[0])
                    if not -(2**63) <= value < 2**64:
                        raise ValueError("Directory integer out of range")
                    values[name] = value
            elif name == "objectclass":
                values[name] = [v.decode("ascii").lower() for v in raw_values]
                if any(not re.fullmatch(r"[a-z0-9-]{1,80}", v) for v in values[name]):
                    raise ValueError("Unsupported directory class")
            else:
                values[name] = [digest(v.decode("utf-8").casefold()) for v in raw_values]
        result.append({"id": digest(dn.casefold()), "attributes": values})
    if len({r["id"] for r in result}) != len(result):
        raise ValueError("Duplicate directory response entries")
    return result


def analyze(snapshot):
    if (not isinstance(snapshot, dict) or set(snapshot) != {"schema_version", "collected_at", "entries", "minimum_password_length"}
            or type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1
            or type(snapshot["minimum_password_length"]) is not int or not 8 <= snapshot["minimum_password_length"] <= 64
            or not isinstance(snapshot["entries"], list) or len(snapshot["entries"]) > 500):
        raise ValueError("Invalid selected directory snapshot")
    _expiry(snapshot["collected_at"])
    declared = {"schema_version": 1, "collected_at": snapshot["collected_at"], **{key: [] for key in ad_review.SECTIONS}}
    extra, inventory = [], {"accounts": 0, "groups": 0, "trusts": 0, "gpo_metadata": 0, "domains": 0}
    omitted = 0
    seen = set()
    for row in snapshot["entries"]:
        if not isinstance(row, dict) or set(row) != {"id", "attributes"} or not isinstance(row["id"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["id"]) or row["id"] in seen:
            raise ValueError("Invalid unique directory identity")
        seen.add(row["id"])
        attr = row["attributes"]
        if not isinstance(attr, dict) or set(attr) - {v.lower() for v in ATTRIBUTES}:
            raise ValueError("Unknown selected directory attributes")
        for key, value in attr.items():
            if key in NUMERIC:
                if type(value) is not int or not -(2**63) <= value < 2**64:
                    raise ValueError("Invalid selected attribute integer")
            elif not isinstance(value, list) or len(value) > 100 or any(not isinstance(v, str) or not re.fullmatch(r"[a-z0-9-]{1,80}", v) for v in value):
                raise ValueError("Invalid selected attribute list")
        classes = attr.get("objectclass", [])
        case = "directory-" + row["id"][:32]

        def add(key, title, fix, severity="WARNING"):
            extra.append({"rule_id": "ad-directory." + key, "test_case": case, "title": title, "severity": severity,
                "cwe": "CWE-284", "remediation": fix, "message": title, "file_path": "external-evidence", "line_start": 1,
                "verification_status": "unverified", "engine": "ad-directory-review"})

        if "user" in classes:
            inventory["accounts"] += 1
            flags = attr.get("useraccountcontrol")
            if flags is not None and not 0 <= flags <= 2**32 - 1:
                raise ValueError("Invalid account control flags")
            account = {"id": case, "enabled": not bool(flags & 2) if flags is not None else None,
                "kind": "computer" if "computer" in classes else "user", "tier0": None,
                "is_domain_controller": bool(flags & 0x2000) if flags is not None else None,
                "user_account_control": flags, "spn_count": len(attr["serviceprincipalname"]) if "serviceprincipalname" in attr else None}
            if len(declared["accounts"]) < 200:
                declared["accounts"].append(account)
            else:
                omitted += 1
            if attr.get("admincount") == 1:
                add("protected-account-review", "Directory account has a protected-account history marker", "Review current privileged memberships and stale adminCount separately; this marker alone does not prove effective administrative privilege.", "INFO")
        if "domaindns" in classes:
            inventory["domains"] += 1
            minimum = attr.get("minpwdlength")
            if minimum is not None and minimum < snapshot["minimum_password_length"]:
                add("password-length-policy", "Collected domain minimum password length is below the approved review baseline", "Review the domain and fine-grained password policies with the owner; align password length, MFA and password screening with the approved policy.")
            if attr.get("lockoutthreshold") == 0:
                add("lockout-policy-review", "Collected domain policy has no account lockout threshold", "Review rate limiting, detection, effective fine-grained policies and denial-of-service tradeoffs; absence alone is not proof of account compromise.", "INFO")
        for class_name, field in (("group", "groups"), ("trusteddomain", "trusts"), ("grouppolicycontainer", "gpo_metadata")):
            inventory[field] += class_name in classes
    report = ad_review.review_evidence(declared)
    report["engine"] = "ad-directory-review"
    report["findings"] += extra
    report["inventory"] = inventory
    report["accounts_omitted_from_legacy_checks"] = omitted
    report["limitations"] = ["Selected server-asserted LDAP attributes; bounded pages may omit accounts, membership ranges and other objects",
        "No effective DACL/AD CS/trust/GPO-content evaluation, password guessing, ticket requests or access-path execution",
        "Domain policies can be overridden by fine-grained policy; adminCount is historical, not proof of effective privilege"]
    return report


class _BoundedSocket:
    def __init__(self, channel, gate):
        self.channel, self.gate, self.received = channel, gate, hashlib.sha256()
        self.count = 0

    def __getattr__(self, name):
        return getattr(self.channel, name)

    def recv(self, amount, *args):
        self.gate(self.channel)
        value = self.channel.recv(min(amount, 65536), *args)
        self.count += len(value)
        if self.count > 1048576:
            raise ValueError("Directory response byte limit reached")
        self.received.update(value)
        return value

    def sendall(self, data, *args):
        self.gate(self.channel)
        if len(data) > 65536:
            raise ValueError("Directory request byte limit reached")
        return self.channel.sendall(data, *args)

    def send(self, data, *args):
        self.gate(self.channel)
        if len(data) > 65536:
            raise ValueError("Directory request byte limit reached")
        return self.channel.send(data, *args)


def collect(path, session_file, session_key, approval, *, authorized=False, stop_file="stop"):
    if authorized is not True:
        raise PermissionError("Directory collection requires --authorized")
    data, credential, fingerprint, ca_raw = contract(path, session_file, session_key)
    if not isinstance(approval, str) or not hmac.compare_digest(approval, fingerprint):
        raise PermissionError("Approve the exact directory contract and credential fingerprint")
    if not isinstance(stop_file, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", stop_file):
        raise ValueError("Use a simple stop basename")
    from ldap3 import Server, Connection, Tls, NONE, SYNC, BASE, SUBTREE, SIMPLE, DEREF_NEVER
    end = time.monotonic() + min(data["timeout_seconds"], (_expiry(data["expires_at"]) - utcnow()).total_seconds())
    stop = _approved_file(path).parent / stop_file
    response = {"source": "ldaps-read-only", "execution_source": data["mode"], "started_at": utcnow().isoformat(), "endpoint_sha256": digest([data["server_ip"], data["server_port"]]),
        "operations": 0, "pages": 0, "complete": False, "error_type": None, "real_provider_verified": False}
    entries = []
    with shared_quota.invocation(data["max_pages"] + 3) as admission:
        response["shared_quota"] = admission.receipt

        def gate(channel=None):
            admission.ensure_active()
            remaining = end - time.monotonic()
            if stop.exists() or remaining <= 0 or contract(path, session_file, session_key)[2] != fingerprint:
                raise PermissionError("Directory stopped, changed or expired")
            if channel is not None:
                channel.settimeout(min(5, remaining))

        class VerifiedTLS(Tls):
            def wrap_socket(self, connection, do_handshake=False):
                gate(connection.socket)
                context = ssl.create_default_context(cadata=ca_raw.decode("ascii") if ca_raw else None)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                secured = context.wrap_socket(connection.socket, server_hostname=data["tls_server_name"])
                connection.socket = _BoundedSocket(secured, gate)

        connection = None
        try:
            gate()
            server = Server(data["server_ip"], port=data["server_port"], use_ssl=True,
                tls=VerifiedTLS(validate=ssl.CERT_REQUIRED), get_info=NONE, connect_timeout=min(5, data["timeout_seconds"]), allowed_referral_hosts=[])
            connection = Connection(server, user=credential["X-LDAP-Bind-DN"], password=credential["Authorization"], authentication=SIMPLE,
                client_strategy=SYNC, auto_referrals=False, auto_range=False, read_only=True, check_names=False,
                raise_exceptions=True, receive_timeout=5, auto_bind=False, lazy=False, use_referral_cache=False)
            response["operations"] += 1
            connection.open(read_server_info=False)
            gate()
            response["operations"] += 1
            if not connection.bind():
                raise PermissionError("Directory bind rejected")
            gate()
            response["operations"] += 1
            connection.search("", "(objectClass=*)", BASE, dereference_aliases=DEREF_NEVER,
                attributes=["defaultNamingContext"], size_limit=1, time_limit=max(1, math.ceil(end - time.monotonic())))
            naming = [{k.lower(): v for k, v in r.get("raw_attributes", {}).items()}.get("defaultnamingcontext", []) for r in connection.response if r.get("type") == "searchResEntry"]
            if (connection.result.get("result") != 0 or len(naming) != 1 or len(naming[0]) != 1
                    or naming[0][0].decode("utf-8").casefold() != data["base_dn"].casefold()):
                raise PermissionError("Directory naming context differs from exact scope")
            cookie = None
            for _ in range(data["max_pages"]):
                gate()
                response["operations"] += 1
                connection.search(data["base_dn"], FILTER, SUBTREE, dereference_aliases=DEREF_NEVER, attributes=list(ATTRIBUTES),
                    size_limit=data["page_size"], time_limit=max(1, math.ceil(end - time.monotonic())),
                    paged_size=data["page_size"], paged_criticality=True, paged_cookie=cookie)
                if connection.result.get("result") not in {0, 4}:
                    raise ValueError("Directory search unavailable")
                if any(r.get("type") != "searchResEntry" for r in connection.response):
                    raise PermissionError("Directory referral or unexpected response refused")
                if any(not r.get("dn", "").casefold().endswith("," + data["base_dn"].casefold()) and r.get("dn", "").casefold() != data["base_dn"].casefold() for r in connection.response):
                    raise PermissionError("Directory response escaped base scope")
                entries.extend(connection.response)
                response["pages"] += 1
                if len(entries) > data["page_size"] * data["max_pages"]:
                    raise ValueError("Directory object limit reached")
                cookie = connection.result.get("controls", {}).get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
                if not cookie:
                    response["complete"] = connection.result.get("result") == 0
                    break
            gate()
            if isinstance(connection.socket, _BoundedSocket):
                response["response_bytes"] = connection.socket.count
                response["response_sha256"] = connection.socket.received.hexdigest()
        except Exception as error:
            response["complete"], response["error_type"] = False, type(error).__name__
        finally:
            if connection is not None:
                try:
                    connection.strategy.close()  # Never send an unapproved post-stop UNBIND.
                except Exception:
                    response["complete"], response["error_type"] = False, "ConnectionCleanupError"
    try:
        normalized = normalize(entries)
    except (ValueError, TypeError, KeyError):
        normalized = []
        response["complete"], response["error_type"] = False, "DirectoryResponseError"
    snapshot = {"schema_version": 1, "collected_at": utcnow().isoformat(), "entries": normalized,
        "minimum_password_length": data["minimum_password_length"]}
    response["finished_at"] = snapshot["collected_at"]
    return snapshot, response
