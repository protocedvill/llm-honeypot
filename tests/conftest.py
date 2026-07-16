import os

os.environ.setdefault("HMAC_SECRET", "test-secret")
os.environ.setdefault("CANARY_BASE_URL", "http://testserver")

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "honeypot-test.sqlite")
    monkeypatch.setenv("DATABASE_PATH", db_path)
    monkeypatch.setenv("HMAC_SECRET", "test-secret")
    monkeypatch.setenv("CANARY_BASE_URL", "http://testserver")
    get_settings.cache_clear()

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client

    get_settings.cache_clear()
