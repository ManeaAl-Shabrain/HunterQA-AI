from pathlib import Path

from hunterqa.scanner import ScanService


def test_semgrep_normalization_hides_absolute_prefix(tmp_path):
    item = {
        "check_id": "hunterqa.python.dangerous-eval",
        "path": str(tmp_path / "src" / "app.py"),
        "start": {"line": 7},
        "end": {"line": 7},
        "extra": {"severity": "ERROR", "message": "Dangerous eval", "lines": "eval(user_input)", "metadata": {"cwe": "CWE-95"}},
    }
    result = ScanService._normalize_semgrep(item, Path(tmp_path))
    assert result["file_path"] == str(Path("src") / "app.py")
    assert result["cwe"] == "CWE-95"
    assert result["line_start"] == 7

