from core.parsers import load_bloodhound_data


def test_bloodhound_parser_supports_node_metadata():
    data = load_bloodhound_data("demo/bloodhound_sample.json")

    assert data["nodes"]["domain_admin"]["admin"] is True
    assert data["relationships"][-1]["label"] == "can_escalate_to"
