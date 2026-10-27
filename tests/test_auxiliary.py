import json
from hunterqa.engines.afl_stats import read_fuzzer_stats
from hunterqa.engines.hypothesis_report import read_hypotheses


def test_afl_stats_are_data_only(tmp_path):
    path=tmp_path/'fuzzer_stats'
    path.write_text('saved_crashes : 1\nexecs_done : 500\ncommand_line : untrusted\n')
    result=read_fuzzer_stats(path)
    assert result['status']=='ready'
    assert result['metrics']['saved_crashes']=='1'
    assert 'command_line' not in result['metrics']


def test_hypotheses_are_never_verified(tmp_path):
    path=tmp_path/'hypotheses.json'
    path.write_text(json.dumps({'model':'qwen2.5-coder:3b','hypotheses':[{'file':'demo.py','potential_weakness':'review','status':'confirmed','zero_day_confirmed':True}]}))
    output=read_hypotheses(path)
    assert output['hypotheses'][0]['status']=='Unverified AI hypothesis'
    assert 'zero_day_confirmed' not in output['hypotheses'][0]
