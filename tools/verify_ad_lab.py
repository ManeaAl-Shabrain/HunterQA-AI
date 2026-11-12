"""Owned Samba AD acceptance inside a disposable network-none Linux container.

Public synthetic credentials only. No host data, mounts or published ports.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

ADMIN = "Owned-Samba-admin-fixture-2026!"  # nosec B105
READER = "Owned-Samba-reader-fixture-2026!"  # nosec B105
LAB_ROOT = Path("/srv/hunterqa-owned-ad")
BASE = "DC=owned,DC=lab,DC=test"


def command(*args):
    result = subprocess.run(list(args), text=True, capture_output=True, timeout=120)  # nosec B603
    if result.returncode:
        raise RuntimeError("Owned lab setup command failed: " + Path(args[0]).name + "\n" + result.stderr[-4000:])
    return result.stdout


def assess():
    from datetime import timedelta
    from hunterqa import ad_directory, assessment_sessions, assessment_modes
    from hunterqa.engagement import utcnow
    if os.geteuid() != 10001:
        raise ValueError("Collector acceptance must run as the dedicated unprivileged reader")
    approved, private = LAB_ROOT / "assessments", LAB_ROOT / "private"
    os.environ["HUNTERQA_APPROVED_ROOTS"] = str(approved)
    os.environ["HUNTERQA_ASSESSMENT_SECRET_ROOT"] = str(private)
    os.environ.pop("HUNTERQA_QUOTA_LEDGER", None)
    from hunterqa.assessment_demo import save
    expiry = (utcnow() + timedelta(minutes=10)).isoformat()
    contract = {"schema_version": 1, "authorization_reference": "Disposable owned Samba AD laboratory only", "acknowledged_authorization": True,
        "expires_at": expiry, "server_ip": "127.0.0.1", "server_port": 636, "allow_private_network": True,
        "mode": "LAB", "tls_server_name": "dc.owned.lab.test", "base_dn": BASE, "ca_file": str(approved / "ca.pem"),
        "max_pages": 5, "page_size": 100, "timeout_seconds": 60, "minimum_password_length": 14}
    source, vault, key = approved / "directory.json", private / "reader.json", private / "reader.key"
    save(source, contract)
    assessment_sessions.create(vault, key, json.dumps({"schema_version": 1, "expires_at": expiry, "actors": {"directory": {
        "origin": "https://dc.owned.lab.test:636", "headers": {"X-LDAP-Bind-DN": "CN=hq-reader,CN=Users," + BASE, "Authorization": READER},
        "cookies": [], "local_storage": {}}}}).encode(), authorized=True)
    approval = ad_directory.preflight(source, vault, key)["approval_sha256"]
    snapshot, receipt = ad_directory.collect(source, vault, key, approval, authorized=True)
    if receipt["error_type"]:
        raise RuntimeError("Owned LDAPS collection failed: " + json.dumps(receipt, sort_keys=True))
    report = ad_directory.analyze(snapshot)
    assert report["inventory"]["accounts"] >= 2 and report["inventory"]["groups"] > 0 and report["inventory"]["domains"] == 1
    rules = {r["rule_id"] for r in report["findings"]}
    assert "ad-directory.password-length-policy" in rules and "ad-directory.lockout-policy-review" in rules
    save(approved / "snapshot.json", snapshot)
    from hashlib import sha256
    shared = assessment_modes.envelope("ad", "LAB", report, [{"sha256": sha256((approved / "snapshot.json").read_bytes()).hexdigest()}], origin="operator-supplied-evidence")
    shared.update(collector="ldaps-read-only", collection=receipt)
    save(approved / "report.json", shared)
    # The snapshot carries selected attributes, never bind credentials or raw DNs.
    text = json.dumps(snapshot) + json.dumps(shared)
    assert ADMIN not in text and READER not in text and "CN=hq-reader" not in text
    assessment_modes.load_report(approved / "report.json")
    print(json.dumps({"engine": "owned-samba-ad-acceptance", "source": "LAB", "actual_samba_ldaps": True,
        "reader_uid": os.geteuid(), "admin_bind_used_by_collector": False, "tls_verified": True,
        "inventory": report["inventory"], "pages": receipt["pages"], "bounded_collection_complete": receipt["complete"],
        "password_policy_rule_observed": True, "external_enterprise_ad_verified": False, "real_cloud_verified": False}, sort_keys=True))


def provision():
    if os.geteuid() != 0 or LAB_ROOT.exists():
        raise ValueError("Owned Samba provisioning requires a fresh disposable container")
    LAB_ROOT.mkdir(mode=0o755)
    LAB_ROOT.chmod(0o711)
    domain = LAB_ROOT / "domain"
    # Test-only user.NTACL avoids granting CAP_SYS_ADMIN to the container.
    # No host filesystem is mounted and no ACL security claims are made.
    command("samba-tool", "domain", "provision", "--realm=OWNED.LAB.TEST", "--domain=OWNED", "--server-role=dc",
        "--dns-backend=SAMBA_INTERNAL", "--host-name=dc", "--host-ip=127.0.0.1", "--targetdir=" + str(domain),
        "--adminpass=" + ADMIN, "--option=acl_xattr:security_acl_name=user.NTACL", "--option=interfaces=lo", "--option=bind interfaces only=yes")
    config = domain / "etc/smb.conf"
    pki = LAB_ROOT / "pki"
    pki.mkdir(mode=0o700)
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Owned Samba laboratory CA",
        "-keyout", str(pki / "ca.key"), "-out", str(pki / "ca.pem"), "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=dc.owned.lab.test", "-keyout", str(pki / "server.key"), "-out", str(pki / "server.csr"))
    ext = pki / "server.ext"
    ext.write_text("subjectAltName=DNS:dc.owned.lab.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    command("openssl", "x509", "-req", "-in", str(pki / "server.csr"), "-CA", str(pki / "ca.pem"), "-CAkey", str(pki / "ca.key"),
        "-CAcreateserial", "-days", "1", "-extfile", str(ext), "-out", str(pki / "server.pem"))
    text = config.read_text()
    text = text.replace("[global]", "[global]\n\ttls enabled = yes\n\ttls keyfile = " + str(pki / "server.key") + "\n\ttls certfile = " + str(pki / "server.pem") + "\n\ttls cafile = " + str(pki / "ca.pem"))
    config.write_text(text)
    command("samba-tool", "user", "create", "hq-reader", READER, "--configfile=" + str(config))
    command("samba-tool", "domain", "passwordsettings", "set", "--min-pwd-length=7", "--account-lockout-threshold=0", "--configfile=" + str(config))
    for name in ("assessments", "private"):
        path = LAB_ROOT / name
        path.mkdir(mode=0o700)
        os.chown(path, 10001, 10001)
    shutil.copyfile(pki / "ca.pem", LAB_ROOT / "assessments/ca.pem")
    os.chown(LAB_ROOT / "assessments/ca.pem", 10001, 10001)
    with (LAB_ROOT / "samba.log").open("w") as log:
        process = subprocess.Popen(["samba", "--foreground", "--no-process-group", "--debug-stdout", "--debuglevel=1", "--configfile=" + str(config)], stdout=log, stderr=log)  # nosec B603
        try:
            end = time.monotonic() + 30
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", 636), timeout=1):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= end:
                        raise RuntimeError("Owned Samba service did not start\n" + (LAB_ROOT / "samba.log").read_text()[-6000:])
                    time.sleep(0.2)
            command("runuser", "-u", "hunterqa-lab-reader", "--", sys.executable, __file__, "--assess")
            # Emit only the sanitized reader receipt, not server identities/logs.
            print(command("runuser", "-u", "hunterqa-lab-reader", "--", "cat", str(LAB_ROOT / "assessments/acceptance.json")))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assess", action="store_true")
    args = parser.parse_args()
    if os.name != "posix" or os.environ.get("HUNTERQA_OWNED_AD_TEST") != "1" or socket.gethostname() != "dc.owned.lab.test":
        raise ValueError("Run only the explicit disposable, isolated owned AD container")
    if args.assess:
        # Capture the sanitized JSON receipt for the root fixture coordinator.
        import contextlib
        with (LAB_ROOT / "assessments/acceptance.json").open("x", encoding="utf-8") as output, contextlib.redirect_stdout(output):
            assess()
    else:
        provision()


if __name__ == "__main__":
    main()
