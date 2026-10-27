import pytest
from hunterqa.cli import _approved_root


def test_cli_denies_unapproved(tmp_path, monkeypatch):
    target = tmp_path / 'target'
    target.mkdir()
    monkeypatch.delenv('HUNTERQA_APPROVED_ROOTS', raising=False)
    monkeypatch.delenv('ZEROSCOPE_APPROVED_ROOTS', raising=False)
    with pytest.raises(ValueError):
        _approved_root(str(target))


def test_cli_accepts_approved(tmp_path, monkeypatch):
    monkeypatch.setenv('HUNTERQA_APPROVED_ROOTS', str(tmp_path))
    assert _approved_root(str(tmp_path)) == tmp_path.resolve()
