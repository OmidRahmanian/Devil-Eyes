"""The open local dashboard: only this computer's browser, on the dashboard's own page, skips the token."""

from __future__ import annotations

import stat

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from starlette.requests import Request

from watchtower.api import create_app
from watchtower.api.local import same_machine
from watchtower.config.settings import AuthSettings, Settings
from watchtower.persistence import Database
from watchtower.services.evidence_store import FilesystemBlobStore

LOCAL = ("127.0.0.1", 50123)


def request(client=LOCAL, **headers):
    raw = [(name.replace("_", "-").encode(), value.encode()) for name, value in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw, "client": client})


@pytest.mark.parametrize("headers", [
    {"host": "localhost:8080"},
    {"host": "127.0.0.1:8080", "origin": "http://127.0.0.1:8080", "sec_fetch_site": "same-origin"},
    {"host": "localhost:8080", "sec_fetch_site": "none"},
])
def test_this_computers_dashboard_page_qualifies(headers):
    assert same_machine(request(**headers))


@pytest.mark.parametrize("client, headers", [
    (("192.168.1.20", 50000), {"host": "localhost:8080"}),  # another device
    (LOCAL, {"host": "attacker.example:8080"}),  # DNS rebinding keeps the attacker's Host
    (LOCAL, {"host": "localhost:8080", "origin": "https://evil.example"}),  # another website
    (LOCAL, {"host": "localhost:8080", "origin": "http://localhost:9999"}),  # another local port
    (LOCAL, {"host": "localhost:8080", "origin": "https://localhost:8080"}),
    (LOCAL, {"host": "localhost:8080", "sec_fetch_site": "cross-site"}),
    (LOCAL, {"host": "localhost:8080", "sec_fetch_site": "same-site"}),
    (None, {"host": "localhost:8080"}),
])
def test_other_devices_sites_and_rebinding_do_not(client, headers):
    assert not same_machine(request(client, **headers))


def app(tmp_path, *, local):
    # No route used here reaches the database, so the engine never connects.
    database = Database(create_engine("postgresql+psycopg://unused@127.0.0.1:9/unused"))
    settings = Settings(auth=AuthSettings(local_dashboard=local, local_owner_token_file=str(tmp_path / "owner")))
    return create_app(database, settings=settings, blobs=FilesystemBlobStore(tmp_path), runs=None)


def test_without_the_setting_a_token_is_always_needed(tmp_path):
    with TestClient(app(tmp_path, local=False), base_url="http://localhost:8080", client=LOCAL) as client:
        assert client.get("/api/v1/projects").status_code == 401
        assert client.post("/api/v1/projects", json={"name": "acme"}).status_code == 403


def test_with_the_setting_strangers_still_need_a_token(tmp_path):
    with TestClient(app(tmp_path, local=True), base_url="http://attacker.example:8080", client=LOCAL) as client:
        assert client.get("/api/v1/projects").status_code == 401
        assert client.post("/api/v1/projects", json={"name": "acme"}).status_code == 403
    with TestClient(app(tmp_path, local=True), base_url="http://localhost:8080", client=("10.0.0.5", 1)) as client:
        assert client.get("/api/v1/projects").status_code == 401
    assert not (tmp_path / "owner").exists()


@pytest.mark.postgres
def test_local_owner_creates_projects_and_adopts_terminal_ones(tmp_path, database):
    settings = Settings(auth=AuthSettings(local_dashboard=True, local_owner_token_file=str(tmp_path / "owner")))
    api = create_app(database, settings=settings, blobs=FilesystemBlobStore(tmp_path), runs=None)
    with database.system() as system:
        terminal = system.projects.create("terminal-made", "Terminal made")
    with TestClient(api, base_url="http://localhost:8080", client=LOCAL) as client:
        created = client.post("/api/v1/projects", json={"name": "Shop.Example.com"},
                              headers={"Origin": "http://localhost:8080"})
        assert created.status_code == 201 and created.json()["slug"] == "shop-example-com"
        assert created.json()["role"] == "owner"
        again = client.post("/api/v1/projects", json={"name": "shop.example.com"}).json()
        assert again["slug"].startswith("shop-example-com-") and again["id"] != created.json()["id"]
        listed = {p["slug"] for p in client.get("/api/v1/projects").json()}
        assert {"shop-example-com", again["slug"], "terminal-made"} <= listed
        assert client.get(f"/api/v1/projects/{terminal.id}/scope").status_code == 200
        # A cross-site page gets nothing, even from this computer.
        assert client.get("/api/v1/projects", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 401
    token = tmp_path / "owner"
    assert stat.S_IMODE(token.stat().st_mode) == 0o600 and token.read_text().startswith("wt_")
