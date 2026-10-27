from hunterqa.engines.trust_graph import build_trust_graph

def test_cross_file_route_to_sink(tmp_path):
    root = tmp_path / 'samplepkg'
    root.mkdir()
    (root/'__init__.py').write_text('')
    (root/'api.py').write_text('from flask import Blueprint, request\nfrom .worker import exec_task\nbp=Blueprint("x",__name__)\n@bp.post("/run")\ndef api_run():\n    command=request.args.get("cmd")\n    return exec_task(command)\n')
    (root/'worker.py').write_text('import subprocess\ndef exec_task(command):\n    return subprocess.run(command, shell=True)\n')
    report=build_trust_graph(root)
    print(report['edges'], report['review_paths'])
    assert report['files_analyzed']==3
    assert len(report['review_paths'])==1
    item=report['review_paths'][0]
    assert item['call_chain']==['samplepkg.api.api_run','samplepkg.worker.exec_task']
    assert item['operation']['cwe_candidate']=='CWE-78'
    assert item['request_reference_observed'] is True
    assert item['taint_flow_confirmed'] is False


def test_safe_shell_not_flagged(tmp_path):
    (tmp_path/'api.py').write_text('import subprocess\nfrom flask import request\n@app.get("/health")\ndef health():\n    return subprocess.run(["echo", "ok"], shell=False)\n')
    assert not build_trust_graph(tmp_path)['review_paths']


def test_symlink_skipped(tmp_path):
    target=tmp_path.parent/'secrets_fixture.py'
    target.write_text('def leak(): eval("1+1")\n')
    (tmp_path/'link.py').symlink_to(target)
    (tmp_path/'local.py').write_text('def local():\n    pass\n')
    result=build_trust_graph(tmp_path)
    assert result['files_analyzed']==1
    assert result['functions']==1
