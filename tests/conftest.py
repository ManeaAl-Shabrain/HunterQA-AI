from __future__ import annotations

import pytest

from hunterqa import create_app


class FakeScanService:
    def __init__(self):
        self.submitted: list[int] = []

    def submit(self, scan_id: int) -> None:
        self.submitted.append(scan_id)


@pytest.fixture()
def approved_root(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    (root / "demo").mkdir()
    return root


@pytest.fixture()
def fake_service():
    return FakeScanService()


@pytest.fixture()
def app(tmp_path, approved_root, fake_service):
    return create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "APPROVED_ROOTS": [str(approved_root)],
        "SCAN_SERVICE": fake_service,
    })


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client) -> str:
    with client.session_transaction() as session:
        session["csrf_token"] = "test-csrf"
    return "test-csrf"

