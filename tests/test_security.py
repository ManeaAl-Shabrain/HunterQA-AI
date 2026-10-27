from __future__ import annotations

import pytest

from hunterqa.security import validate_project_path


def test_accepts_directory_inside_approved_root(app, approved_root):
    with app.app_context():
        assert validate_project_path(str(approved_root / "demo")) == (approved_root / "demo").resolve()


def test_rejects_directory_outside_approved_root(app, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    with app.app_context(), pytest.raises(ValueError, match="outside"):
        validate_project_path(str(outside))


def test_rejects_missing_path(app, approved_root):
    with app.app_context(), pytest.raises(FileNotFoundError):
        validate_project_path(str(approved_root / "missing"))

