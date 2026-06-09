import networkx as nx

from core.analysis.path_analyzer import AttackPathAnalyzer


def test_attack_path_enumeration_is_bounded():
    graph = nx.DiGraph()
    graph.add_node("entry", type="service")
    graph.add_node("critical", type="user", admin=True)
    graph.add_edges_from(
        [
            ("entry", "left"),
            ("left", "critical"),
            ("entry", "right"),
            ("right", "critical"),
        ]
    )

    analyzer = AttackPathAnalyzer(graph, max_paths=1, max_path_length=5)
    paths = analyzer.find_all_attack_paths(["entry"], ["critical"])

    assert len(paths) == 1
    assert analyzer.paths_truncated is True
