import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
os.environ["BONGO_WEATHER_ONLINE"] = "0"
os.environ["BONGO_LLM_PROVIDER"] = "offline"
PASSWORD = "BongoDemo!2026"
os.environ["BONGO_DEMO_PASSWORD"] = PASSWORD


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    from bongo_ai.config import settings
    import seed
    path = tmp_path_factory.mktemp("db") / "test.db"
    seed.build(path, keep_dates=False, days=31)
    settings.db_path = path
    from fastapi.testclient import TestClient
    from bongo_ai.app import app
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """The app allows 20 logins a minute per IP; the suite logs in more often than that."""
    yield
    from bongo_ai import app as app_module
    app_module._hits.clear()


@pytest.fixture(scope="session")
def login(client):
    cache = {}

    def _login(username: str) -> dict:
        if username not in cache:
            r = client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()
            assert r["isSuccess"], r
            cache[username] = {"Authorization": f"Bearer {r['token']}"}
        return cache[username]
    return _login


def invoke(client, headers, name, args=None, user_message=""):
    r = client.post(f"/api/tools/{name}/invoke", headers=headers,
                    json={"arguments": args or {}, "userMessage": user_message})
    assert r.status_code == 200, r.text
    return r.json()
