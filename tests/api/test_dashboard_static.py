"""The dashboard renders captured content as text and runs under a strict CSP."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from watchtower.api import create_app
from watchtower.persistence import Database
from watchtower.services.evidence_store import FilesystemBlobStore

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
# Our own scripts; the vendored Three.js build is checked by hash instead.
SCRIPTS = ["app.js", "cosmos.js", "target-page.js", "add-target.js",
           *sorted(p.relative_to(FRONTEND).as_posix() for p in (FRONTEND / "universe").glob("*.js"))]
THREE = FRONTEND / "vendor" / "three.module.min.js"
THREE_SHA256 = "08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7"


def test_script_never_parses_data_as_html_or_code():
    for name in SCRIPTS:
        script = (FRONTEND / name).read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                     "setTimeout(\"", "javascript:"):
            assert sink not in script, (name, sink)


def test_scripts_import_only_same_origin_modules():
    for name in SCRIPTS:
        script = (FRONTEND / name).read_text(encoding="utf-8")
        for match in re.finditer(r'(?:from\s+|import\()\s*"([^"]+)"', script):
            assert match.group(1).startswith(("./", "../", "/static/")), (name, match.group(1))


def test_vendored_three_is_pinned_and_licensed():
    assert hashlib.sha256(THREE.read_bytes()).hexdigest() == THREE_SHA256
    assert (FRONTEND / "vendor" / "three.LICENSE.txt").read_text(encoding="utf-8").startswith("The MIT License")
    notices = (Path(__file__).resolve().parents[2] / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "three.js" in notices and "0.170.0" in notices


def test_page_has_no_inline_code_or_styles():
    page = (FRONTEND / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", page)
    assert not re.search(r"\son[a-z]+=", page)
    assert "style=" not in page and "<style" not in page


@pytest.fixture
def client(tmp_path):
    # No route used here touches the database, so the engine never connects.
    database = Database(create_engine("postgresql+psycopg://unused@127.0.0.1:9/unused"))
    with TestClient(create_app(database, blobs=FilesystemBlobStore(tmp_path), runs=None)) as test_client:
        yield test_client


def test_dashboard_and_assets_are_served_with_security_headers(client):
    page = client.get("/")
    assert page.status_code == 200 and "Devils Eyes" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp and "frame-ancestors 'none'" in csp
    script = client.get("/static/app.js")
    assert script.status_code == 200 and script.headers["x-content-type-options"] == "nosniff"
    # Module scripts are refused unless served with a JavaScript type.
    for path in ("/static/universe/index.js", "/static/vendor/three.module.min.js"):
        module = client.get(path)
        assert module.status_code == 200 and "javascript" in module.headers["content-type"], path
    assert client.get("/static/../pyproject.toml").status_code == 404


def test_no_third_party_docs_pages_on_the_dashboard_origin(client):
    assert client.get("/api/v1/docs").status_code == 404
    assert client.get("/api/v1/openapi.json").json()["info"]["title"] == "Devils Eyes"
