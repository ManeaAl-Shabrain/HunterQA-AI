"""Original native-format fixtures, not Windows application/provider validation."""
import hashlib
import json
import struct

import pytest

from hunterqa import assessment_modes, gpo_review
from hunterqa.cli import main


def inf(body):
    return b"\xff\xfe" + ('[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature="$CHICAGO$"\r\nRevision=1\r\n' + body).encode("utf-16-le")


def pol(*records):
    data = b"PReg\x01\x00\x00\x00"
    for key, name, kind, value in records:
        if isinstance(value, int):
            value = struct.pack("<I" if kind == 4 else ">I", value)
        data += ("[" + key + "\0;" + name + "\0;").encode("utf-16-le")
        data += struct.pack("<I", kind) + b";\0" + struct.pack("<I", len(value)) + b";\0" + value + b"]\0"
    return data


def review(raw, mode="gpo-security-template"):
    return gpo_review.review_bytes(raw, mode=mode)


def test_native_security_template_positive_negative_privacy_and_unknowns():
    unsafe = inf('[System Access]\r\nMinimumPasswordLength=7\r\nClearTextPassword=1\r\nLockoutBadCount=0\r\n'
        '[Privilege Rights]\r\nSeDebugPrivilege=*S-1-5-11,PRIVATE\\alice\r\n'
        '[Registry Values]\r\nMACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature=4,0\r\n'
        '[File Security]\r\n"C:\\private-path",0,"private-descriptor"\r\n')
    report = review(unsafe)
    assert {r["rule_id"] for r in report["findings"]} == {"gpo.password-length-below-eight", "gpo.reversible-password-storage",
        "gpo.lockout-disabled-review", "gpo.broad-sensitive-privilege", "gpo.smb-signing-not-required"}
    assert report["unsupported_directives"] == 2 and not report["effective_policy_verified"]
    assert report["input_sha256"] == hashlib.sha256(unsafe).hexdigest()
    for private in ("alice", "PRIVATE", "private-path", "S-1-5-11", "private-descriptor"):
        assert private not in json.dumps(report)
    safe = review(inf('[System Access]\r\nMinimumPasswordLength=14\r\nClearTextPassword=0\r\nLockoutBadCount=10\r\n'
        '[Privilege Rights]\r\nSeDebugPrivilege=*S-1-5-32-544\r\n'))
    assert not safe["findings"] and safe["selected_directives_reviewed"] == 4


@pytest.mark.parametrize("body", [
    '[System Access]\r\nClearTextPassword=2\r\n', '[System Access]\r\nMinimumPasswordLength=-1\r\n',
    '[System Access]\r\nMinimumPasswordLength=8\r\nMINIMUMPASSWORDLENGTH=7\r\n',
    '[System Access]\r\n[system access]\r\n', '[System Access]\r\nMissingEquals\r\n',
    '[Registry Values]\r\nMACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,99999999999\r\n'])
def test_malformed_selected_template_is_rejected_without_echoing_values(body):
    with pytest.raises(ValueError):
        review(inf(body))


@pytest.mark.parametrize("raw", [b"[System Access]\nMinimumPasswordLength=7", b"\xff\xfe\x00", inf('[System Access]\n'),
    inf('[System Access]\r\nX=\x00\r\n'), b"\xff\xfe" + '[Version]\r\nsignature="other"\r\nRevision=1\r\n'.encode('utf-16-le')])
def test_encoding_version_and_null_fail_closed(raw):
    with pytest.raises(ValueError):
        review(raw)


@pytest.mark.parametrize("key,name,unsafe,safe", [
    (r'SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 2, 5),
    (r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'RequireSecuritySignature', 0, 1),
    (r'SYSTEM\CurrentControlSet\Services\LDAP', 'LDAPClientIntegrity', 0, 2),
    (r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 1, 0)])
def test_binary_registry_positive_negative_and_order(key, name, unsafe, safe):
    first = review(pol((key, name, 4, unsafe)), 'gpo-machine-registry')
    assert len(first['findings']) == 1
    ordered = review(pol((key, name, 4, unsafe), (key.lower(), name.lower(), 5, safe)), 'gpo-machine-registry')
    assert not ordered['findings'] and ordered['overwritten_registry_assignments'] == 1
    assert ordered['selected_directives_reviewed'] == 1


def test_special_registry_program_or_unsupported_type_does_not_claim_scalar_result():
    key = r'SYSTEM\CurrentControlSet\Control\Lsa'
    raw = pol((key, 'LmCompatibilityLevel', 4, 2), (key, '**Del.LmCompatibilityLevel', 1, b'\0\0'))
    report = review(raw, 'gpo-machine-registry')
    assert report['registry_program_requires_review'] and not report['findings']
    assert report['unsupported_directives'] == 2 and report['selected_directives_reviewed'] == 0
    report = review(pol((key, 'LmCompatibilityLevel', 1, b'2\0\0\0')), 'gpo-machine-registry')
    assert report['unsupported_directives'] == 1 and not report['findings']
    report = review(pol((key, 'LmCompatibilityLevel', 4, 99)), 'gpo-machine-registry')
    assert report['unsupported_directives'] == 1 and report['selected_directives_reviewed'] == 0
    report = review(inf('[Privilege Rights]\r\nSeDebugPrivilege=PRIVATE\\unknown\r\n'))
    assert report['observations'][0]['state'] == 'insufficient-evidence'
    assert report['unresolved_identity_references'] == 1


def test_all_truncations_and_invalid_binary_lengths_are_rejected():
    raw = pol((r'SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 4, 2))
    for end in range(len(raw)):
        if end == 8:  # An empty valid header contains no setting.
            continue
        with pytest.raises(ValueError):
            review(raw[:end], 'gpo-machine-registry')
    for bad in (b'PReg\2\0\0\0', raw + b'\x00', pol(('A', 'B', 4, b'\0')), pol(('A', 'B', 11, b'\0' * 4))):
        with pytest.raises(ValueError):
            review(bad, 'gpo-machine-registry')


def test_size_and_record_limits():
    with pytest.raises(ValueError):
        review(b'x' * (gpo_review.MAX_BYTES + 1))
    with pytest.raises(ValueError):
        review(pol(*[('A', 'B', 4, 0)] * 1001), 'gpo-machine-registry')
    with pytest.raises(ValueError):
        review(inf('[System Access]\r\n' + ''.join(f'unknown{i}=1\r\n' for i in range(1001))))


def test_shared_cli_history_schema_export_and_authorization(tmp_path, monkeypatch):
    monkeypatch.setenv('HUNTERQA_APPROVED_ROOTS', str(tmp_path))
    source = tmp_path / 'GptTmpl.inf'
    source.write_bytes(inf('[System Access]\r\nClearTextPassword=1\r\n'))
    output = tmp_path / 'report.json'
    args = ['assessment-review', '--module', 'ad', '--mode', 'LAB', '--input-mode', 'gpo-security-template',
        '--input', str(source), '--out', str(output)]
    with pytest.raises(PermissionError):
        main(args)
    main([*args, '--authorized'])
    report = assessment_modes.load_report(output)
    assert report['analysis_limits']['effective_policy_verified'] is False
    assert report['analysis_engine'] == 'native-gpo-file-review' and report['execution_source'] == 'LAB'
    assert report['evidence'][0]['sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert report['findings'][0]['evidence_ids'] and not report['real_provider_verified']
    for kind in ('json', 'html', 'sarif'):
        assert 'LAB' in assessment_modes.export(output, kind)
    forged = tmp_path / 'forged.json'
    report['analysis_limits']['effective_policy_verified'] = True
    forged.write_text(json.dumps(report))
    with pytest.raises(ValueError, match='GPO coverage or verification'):
        assessment_modes.load_report(forged)
    with pytest.raises(ValueError):
        assessment_modes.analyze('ad', source, mode='LIVE', input_mode='unsupported', authorized=True)


def test_native_parser_never_opens_network_or_executes_source(tmp_path, monkeypatch):
    import socket
    monkeypatch.setenv('HUNTERQA_APPROVED_ROOTS', str(tmp_path))
    def blocked(*args, **kwargs):
        raise AssertionError('No network permitted')
    monkeypatch.setattr(socket, 'socket', blocked)
    source = tmp_path / 'Registry.pol'
    source.write_bytes(pol(('Unselected', 'NeverExecute', 1, 'import os;raise RuntimeError()\0'.encode('utf-16-le'))))
    assert not gpo_review.review_file(source, mode='gpo-machine-registry', authorized=True)['findings']


def test_gpo_result_is_recorded_in_existing_protected_dashboard_history(tmp_path, monkeypatch):
    from hunterqa import create_app, assessment_history
    from tests import test_workspaces as ws
    spaces = ws.spaces.__wrapped__(tmp_path, monkeypatch)
    root = spaces[1][0] / 'assessments'
    source, output = root / 'GptTmpl.inf', root / 'gpo-result.json'
    original = inf('[System Access]\r\nClearTextPassword=1\r\n[Event Audit]\r\nAuditSystemEvents=0\r\n')
    source.write_bytes(original)
    main(['assessment-review', '--module', 'ad', '--mode', 'LAB', '--input-mode', 'gpo-security-template',
        '--input', str(source), '--out', str(output), '--workspace-config', str(spaces[2][0]), '--authorized'])
    assert source.read_bytes() == original
    app = create_app({'WORKSPACE_CONFIG': str(spaces[2][0]), 'TESTING': True})
    runs = assessment_history.history(app.config['DATABASE'])
    assert len(runs) == 1 and runs[0]['kind'] == 'unified-assessment-review:LAB:ad'
    client = app.test_client()
    target = '/scenarios/' + str(runs[0]['id'])
    assert client.get(target).status_code == 302
    ws._login(client)
    assert b'reversible password storage' in client.get(target).data
    assert b'Unassessed directives: 1' in client.get(target).data
    assert b'Effective Windows policy has not been verified' in client.get(target + '/export.html').data
    assert client.get(target + '/export.sarif').status_code == 200
    binary_source, binary_output = root / 'Registry.pol', root / 'registry-result.json'
    binary_source.write_bytes(pol(('Unselected', '**DelVals', 1, b'\0\0')))
    main(['assessment-review', '--module', 'ad', '--mode', 'LAB', '--input-mode', 'gpo-machine-registry',
        '--input', str(binary_source), '--out', str(binary_output), '--workspace-config', str(spaces[2][0]), '--authorized'])
    second = assessment_history.history(app.config['DATABASE'])[0]['id']
    page = client.get('/scenarios/' + str(second)).data
    assert b'No selected GPO directive was assessed' in page and b'Registry operations were not evaluated' in page
    sarif = client.get('/scenarios/' + str(second) + '/export.sarif').json
    assert sarif['runs'][0]['properties']['gpoCoverage']['registry_program_requires_review']
    assert sarif['runs'][0]['properties']['gpoCoverage']['selected_directives_reviewed'] == 0
    output.write_text('{}')
    assert client.get(target + '/export.json').status_code == 404
