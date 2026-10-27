from hunterqa.engines.ai_research import source_samples


def test_only_bounded_local_source_files(tmp_path):
    (tmp_path / 'main.py').write_text('print("hello")')
    (tmp_path / '.env').write_text('PASSWORD=secret')
    samples=source_samples(tmp_path)
    assert len(samples)==1
    assert samples[0]['file']=='main.py'
    assert 'PASSWORD' not in str(samples)
