import networkx as nx

from core.web.web_interface import WebInterface


def test_health_endpoint_returns_ok():
    web = WebInterface(graph=nx.DiGraph())

    response = web.app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
