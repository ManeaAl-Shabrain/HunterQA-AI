from pathlib import Path
import pytest
from hunterqa.engines.fuzzing import verify_crashes
from hunterqa.engines.sanitizers import parse_sanitizer_log


def test_verify_requires_authorization(tmp_path):
    b = tmp_path / 'binary'
    b.write_bytes(b'not executable')
    c = tmp_path / 'crashes'
    c.mkdir()
    with pytest.raises(PermissionError):
        verify_crashes(approved_lab=tmp_path, binary_path=b, crash_dir=c,
                       output=tmp_path / 'out.json', authorized=False)


def test_runtime_crash_and_sanitizer_claims_separate():
    asan = parse_sanitizer_log('ERROR: AddressSanitizer: heap-use-after-free\n')
    abort = parse_sanitizer_log('SIGABRT: intentional abort')
    assert asan['cwe_candidate'] == 'CWE-416'
    assert abort['cwe_candidate'] is None
    assert asan['zero_day_confirmed'] is False
