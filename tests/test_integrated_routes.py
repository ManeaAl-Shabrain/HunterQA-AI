import json
from .conftest import csrf


def test_capabilities_and_audit(client):
    assert client.get('/capabilities').status_code == 200
    assert b'Manual research required' in client.get('/capabilities').data
    assert client.get('/audit').status_code == 200


def test_research_snapshot_and_export(client, app, tmp_path):
    p = tmp_path / 'integrated.json'
    p.write_text(json.dumps({"project": "HunterQA AI", "findings": [{"filename": "case", "attempts": [{"signal": 6}]}], "sanitizer_evidence": []}))
    app.config['RESEARCH_REPORT_PATH'] = str(p)
    assert client.get('/research').status_code == 200
    status = client.get('/api/research/evidence').get_json()
    assert status['findings_count'] == 1
    export = client.get('/api/research/export')
    assert export.status_code == 200
    assert export.get_json()['evidence']['findings'][0]['signal'] == 6
    assert export.get_json()['evidence']['summary']['zero_days_confirmed'] == 0


def test_audit_event_written(client, approved_root, app):
    from hunterqa.db import connect
    response = client.post('/projects', data={'csrf_token': csrf(client), 'name': 'Safe local repo', 'path': str(approved_root / 'demo')})
    assert response.status_code == 302
    with connect(app.config['DATABASE']) as db:
        row = db.execute("SELECT action FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    assert row['action'] == 'project_registered'
