import networkx as nx
from pathlib import Path
import shutil
import subprocess
from base64 import b64encode

import pytest

from core.web.web_interface import WebInterface


def test_health_endpoint_returns_ok():
    web = WebInterface(graph=nx.DiGraph())

    response = web.app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_security_headers_are_applied():
    web = WebInterface(graph=nx.DiGraph())

    response = web.app.test_client().get("/healthz")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_generated_javascript_escapes_imported_data():
    web = WebInterface(graph=nx.DiGraph())

    graph_js = Path(web.static_dir, "js", "graph.js").read_text(encoding="utf-8")
    app_js = Path(web.static_dir, "js", "app.js").read_text(encoding="utf-8")
    styles = Path(web.static_dir, "css", "styles.css").read_text(encoding="utf-8")

    assert "function escapeHtml" in graph_js
    assert "escapeHtml(data.description" in graph_js
    assert "escapeHtml(technique.name)" in app_js
    assert "'X-Requested-With': 'AttackPathGraph'" in app_js
    assert "'X-CSRF-Token': csrfToken" in app_js
    assert "const attackPaths = this.data.attack_paths || []" in graph_js
    assert "position: relative" in styles


def test_generated_javascript_is_valid():
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")

    web = WebInterface(graph=nx.DiGraph())
    scripts = [
        Path(web.static_dir, "js", "graph.js"),
        Path(web.static_dir, "js", "app.js"),
    ]

    for script in scripts:
        subprocess.run(["node", "--check", str(script)], check=True)


def test_mutating_routes_reject_requests_without_app_header():
    web = WebInterface(graph=nx.DiGraph())
    client = web.app.test_client()

    export_response = client.post("/api/export/neo4j")
    report_response = client.post("/generate-report")

    assert export_response.status_code == 403
    assert report_response.status_code == 403


def test_neo4j_web_export_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ATTACKPATHGRAPH_ENABLE_NEO4J_EXPORT", raising=False)
    web = WebInterface(graph=nx.DiGraph())

    response = web.app.test_client().post(
        "/api/export/neo4j",
        headers={
            "X-Requested-With": "AttackPathGraph",
            "X-CSRF-Token": web.csrf_token,
        },
    )

    assert response.status_code == 403
    assert "désactivé" in response.get_json()["error"]


def test_csrf_token_is_required_for_mutating_routes():
    web = WebInterface(graph=nx.DiGraph())

    response = web.app.test_client().post(
        "/generate-report",
        headers={"X-Requested-With": "AttackPathGraph"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Invalid CSRF token"


def test_basic_auth_protects_graph_data(monkeypatch):
    monkeypatch.setenv("ATTACKPATHGRAPH_AUTH_USERNAME", "analyst")
    monkeypatch.setenv("ATTACKPATHGRAPH_AUTH_PASSWORD", "strong-password")
    web = WebInterface(graph=nx.DiGraph())
    client = web.app.test_client()

    denied = client.get("/api/graph")
    token = b64encode(b"analyst:strong-password").decode("ascii")
    allowed = client.get("/api/graph", headers={"Authorization": f"Basic {token}"})

    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_health_check_does_not_require_authentication(monkeypatch):
    monkeypatch.setenv("ATTACKPATHGRAPH_AUTH_USERNAME", "analyst")
    monkeypatch.setenv("ATTACKPATHGRAPH_AUTH_PASSWORD", "strong-password")
    web = WebInterface(graph=nx.DiGraph())

    response = web.app.test_client().get("/healthz")

    assert response.status_code == 200


def test_rate_limit_rejects_excess_requests(monkeypatch):
    monkeypatch.setenv("ATTACKPATHGRAPH_RATE_LIMIT", "2")
    web = WebInterface(graph=nx.DiGraph())
    client = web.app.test_client()

    assert client.get("/api/security").status_code == 200
    assert client.get("/api/security").status_code == 200
    assert client.get("/api/security").status_code == 429


def test_remote_bind_requires_authentication():
    web = WebInterface(graph=nx.DiGraph())

    with pytest.raises(RuntimeError, match="without authentication"):
        web.start(host="0.0.0.0", open_browser=False)


def test_debug_mode_is_restricted_to_loopback(monkeypatch):
    monkeypatch.setenv("ATTACKPATHGRAPH_AUTH_USERNAME", "analyst")
    monkeypatch.setenv("ATTACKPATHGRAPH_AUTH_PASSWORD", "strong-password")
    web = WebInterface(graph=nx.DiGraph())

    with pytest.raises(RuntimeError, match="debug mode"):
        web.start(host="0.0.0.0", debug=True, open_browser=False)
